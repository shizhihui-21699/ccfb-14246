# frozen_string_literal: true

module BecDetector
  # 单条证据。direction: +1 为可疑证据，-1 为可信证据（负分）。
  Signal = Struct.new(:id, :direction, :score, :reason, :layer, keyword_init: true)

  # 信号引擎：把邮件与身份图谱比对，产出一组带权重、带中文解释的证据。
  # 设计原则：
  #   1. 身份层证据（仿冒域名、免费邮箱冒充显示名）权重最高；
  #   2. 内容语义只做加权，绝不单独拦截（正常邮件也会谈付款）；
  #   3. 可信证据以负分参与加总，用于抑制误报（登记过的私人邮箱、历史往来）；
  #   4. 难点3（邮箱真的被盗，SPF/DKIM 全过）由线程层+行为层证据兜底。
  class SignalEngine
    # 各历史线程的固有话题关键词，用于识别“回复旧线程却谈新事情”
    THREAD_TOPICS = {
      "TH-HY-01" => %w[供货 订单 交货 发货 采购],
      "TH-HY-02" => %w[供货 报价 样品],
      "TH-BO-01" => %w[并购 收购 尽调 交割 标的],
      "TH-QM-01" => %w[回款 账单 结算],
      "TH-LAW-01" => %w[合同 法务 诉讼 协议],
      "TH-AUDIT" => %w[审计 报表 底稿 凭证],
      "TH-INTERNAL-01" => %w[预算 审批 费用],
      "TH-INTERNAL-02" => %w[报销 工资 税务]
    }.freeze

    def initialize(graph)
      @graph = graph
      @domains = DomainAnalyzer.new(graph)
    end

    def evaluate(email)
      signals = []
      signals.concat(identity_signals(email))
      signals.concat(auth_signals(email))
      signals.concat(thread_signals(email))
      signals.concat(behavior_signals(email))
      signals.concat(trust_signals(email))
      signals
    end

    private

    # ---------- 第一层：身份与域名 ----------
    def identity_signals(email)
      out = []
      da = @domains.analyze(email.from_address)
      tf = TextFeatures.new(email)
      display = email.normalized_display_name
      impersonated_emp = display && @graph.match_employee_by_display(display)
      impersonated_partner = display && @graph.partner_by_name(display)

      case da.kind
      when :lookalike_corp
        out << sig(:S01, 38,
                   "仿冒公司域名：#{email.from_domain} 与公司域 #{@graph.corp_domain} 高度相似——#{da.techniques.join('；')}",
                   "身份层")
      when :lookalike_partner
        out << sig(:S02, 25,
                   "仿冒合作方域名：#{email.from_domain} 仿冒#{da.target_name}的域 #{da.target_domain}——#{da.techniques.join('；')}",
                   "身份层")
      end

      if da.kind == :free_mail
        if impersonated_emp
          # 登记过的私人邮箱是合法别名，走 S19 信任信号；未登记则高度可疑
          unless @graph.known_corp_address?(email.from_address)
            out << sig(:S03, 28,
                       "免费邮箱 #{email.from_domain} 却使用内部人员“#{impersonated_emp.name}（#{impersonated_emp.role}）”的显示名，" \
                       "且该私人邮箱未在公司登记",
                       "身份层")
          end
        elsif impersonated_partner && !@graph.known_partner_address?(email.from_address)
          out << sig(:S04, 14,
                     "免费邮箱 #{email.from_domain} 使用合作方“#{impersonated_partner.name}”的显示名，且不是其登记联系人",
                     "身份层")
        else
          out << sig(:S05, 5, "发件域为免费邮箱 #{email.from_domain}，与公司及合作方均无登记关系", "身份层")
        end
      end

      if da.kind == :unknown
        if impersonated_emp
          out << sig(:S06, 16,
                     "未知外部域 #{email.from_domain} 使用内部人员“#{impersonated_emp.name}”的显示名",
                     "身份层")
        elsif impersonated_partner
          out << sig(:S07, 8,
                     "未知外部域 #{email.from_domain} 使用合作方“#{impersonated_partner.name}”的显示名（可能是对方换邮箱，先复核）",
                     "身份层")
        else
          out << sig(:S08, 3, "发件域 #{email.from_domain} 为首次出现的未知外部域", "身份层")
        end
      end

      # 显示名与本地部分不一致（如显示 CEO，本地部分却是一串无关字符）
      if impersonated_emp && da.kind != :corp &&
         !email.from_local.include?(impersonated_emp.pinyin[0, 4]) &&
         !@graph.known_corp_address?(email.from_address)
        out << sig(:S09, 8,
                   "显示名自称“#{impersonated_emp.name}”，但邮箱本地部分“#{email.from_local}”与其姓名拼音无关",
                   "身份层")
      end
      out
    end

    # ---------- 第二层：发件认证 ----------
    def auth_signals(email)
      out = []
      email.auth_failures.each do |m|
        out << sig(:S10, 14, "发件认证 #{m.upcase} 未通过，邮件可能并非来自该地址或在传输中被伪造", "认证层")
      end
      if email.reply_to && email.reply_to.downcase.split("@", 2).last != email.from_domain
        out << sig(:S11, 12,
                   "Reply-To 指向 #{email.reply_to}，与发件域 #{email.from_domain} 不一致（典型“回信劫持”手法）",
                   "认证层")
      end
      out
    end

    # ---------- 第三层：线程与关系 ----------
    def thread_signals(email)
      out = []
      tid = email.thread_id
      if tid
        participants = @graph.thread_participants(tid)
        if participants.any? && !participants.include?(email.from_address.downcase)
          out << sig(:S12, 14,
                     "发件人 #{email.from_address} 从未在线程 #{tid} 中出现过，属于陌生地址介入已有往来（线程入侵）",
                     "线程层")
        end
        topics = THREAD_TOPICS[tid]
        if topics && email.reply? && TextFeatures.new(email).topic_shift?(email, topics) &&
           TextFeatures.new(email).payment_request?
          out << sig(:S13, 16,
                     "回复的是历史线程 #{tid}（原话题：#{topics.first(3).join('、')}），正文却转向资金请求，话题发生突变",
                     "线程层")
        end
      elsif TextFeatures.new(email).payment_request?
        out << sig(:S14, 4, "带资金请求的邮件没有任何历史往来线程（冷启动付款请求）", "线程层")
      end
      out
    end

    # ---------- 第四层：行为与语义 ----------
    def behavior_signals(email)
      out = []
      tf = TextFeatures.new(email)
      emp = @graph.employee_by_email(email.from_address)
      partner = @graph.partner_by_domain(email.from_domain)
      known_sender = !emp.nil? || @graph.known_partner_address?(email.from_address)

      if tf.bec_triad?
        out << sig(:S15, 12, "同时出现#{tf.explain(:payment)}、#{tf.explain(:urgency)}、#{tf.explain(:secrecy)}，" \
                             "构成“催款+保密”的典型欺诈话术组合", "行为层")
      else
        out << sig(:S16, 6, tf.explain(:bank_change), "行为层") if tf.present?(:bank_change)
        out << sig(:S16, 5, tf.explain(:payment), "行为层") if tf.present?(:payment)
        out << sig(:S16, 3, tf.explain(:urgency), "行为层") if tf.present?(:urgency)
        out << sig(:S16, 3, tf.explain(:secrecy), "行为层") if tf.present?(:secrecy)
      end
      out << sig(:S16, 4, tf.explain(:mna), "行为层") if tf.present?(:mna)
      out << sig(:S16, 3, tf.explain(:authority), "行为层") if tf.present?(:authority)
      out << sig(:S16, 2, tf.explain(:generic_greeting), "行为层") if tf.generic_greeting?

      # S23（难点3核心）：可信发件人（认证全过、域名真实）突然要求变更收款账户。
      # 真实的账户变更函会强调走流程、电话确认；诈骗邮件直接要求按新账号付款。
      if known_sender && tf.present?(:bank_change)
        process_words = %w[流程 确认 函 备案 证明 生效 正式]
        process_framed = process_words.any? { |w| email.body.to_s.include?(w) }
        if process_framed
          out << sig(:S24, -10,
                     "虽涉及账户变更，但措辞为正式变更流程（含书面函/确认/备案表述），符合真实变更的沟通模式",
                     "行为层")
        else
          out << sig(:S23, 32,
                     "可信发件人突然通知收款账户变更且未提及任何变更流程/书面确认，" \
                     "与“邮箱被盗后改款诈骗”的行为模式高度吻合",
                     "行为层")
        end
      end

      # S25：可信内部员工发出与其角色不符的越权资金指令
      if emp && %w[出纳 普通员工 HR经理 IT经理].include?(emp.role) &&
         (tf.present?(:authority) || (tf.present?(:payment) && tf.present?(:urgency)))
        out << sig(:S25, 12,
                   "发件人角色为#{emp.role}，职责上不发起资金/行政指令，本邮件却出现指令式或催款口吻（角色偏离）",
                   "行为层")
      end

      # S26：要求绕过审批流程——BEC 的强意图信号，正常内部邮件不会这样写
      bypass_words = %w[不用走流程 不要走流程 跳过流程 先付 先转 特批 事后补 回来补 不用审批 直接安排]
      hit = bypass_words.find { |w| email.body.to_s.include?(w) }
      if hit
        out << sig(:S26, 10, "邮件明确要求规避正常审批流程（命中表述：“#{hit}”）", "行为层")
      end

      # 非资金类合作方（律所/审计）突然谈钱
      if partner && !partner.payment_capable && tf.payment_request?
        out << sig(:S17, 8, "#{partner.name}属于非资金类合作方（历史无付款往来），却在邮件中发起资金请求", "行为层")
      end

      out << sig(:S18, 2, "邮件带外部链接", "行为层") if email.has_link
      out << sig(:S18, 2, "邮件带附件", "行为层") if email.has_attachment
      out
    end

    # ---------- 可信证据（负分，抑制误报） ----------
    def trust_signals(email)
      out = []
      emp = @graph.employee_by_email(email.from_address)
      da = @domains.analyze(email.from_address)

      if da.kind == :corp
        out << sig(:S19, -12, "发件域为公司主域且地址属于在册员工 #{emp&.name}", "信任层")
      elsif emp
        out << sig(:S19, -8,
                   "发件地址 #{email.from_address} 是员工 #{emp.name}（#{emp.role}）在公司登记过的私人邮箱别名",
                   "信任层")
      end

      if @graph.known_partner_address?(email.from_address)
        p = @graph.partners.find { |x| x.contact_emails.map(&:downcase).include?(email.from_address.downcase) }
        out << sig(:S20, -8, "发件地址是合作方“#{p&.name}”的登记联系人邮箱", "信任层")
      end
      if email.thread_id && @graph.seen_on_thread?(email.thread_id, email.from_address)
        out << sig(:S21, -4, "发件地址在本线程的历史往来中出现过", "信任层")
      end
      if @graph.in_address_book?(email.from_address) && !emp && !@graph.known_partner_address?(email.from_address)
        out << sig(:S22, -3, "发件地址存在于公司通讯录/历史通信记录", "信任层")
      end
      out
    end

    def sig(id, score, reason, layer)
      Signal.new(id: id, direction: score.positive? ? 1 : -1, score: score, reason: reason, layer: layer)
    end
  end
end
