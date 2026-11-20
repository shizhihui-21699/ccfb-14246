# frozen_string_literal: true

module BecDetector
  # 文本特征：不判断“文字是否正常”（BEC 邮件的文字通常完全正常），
  # 只抽取与资金欺诈强相关的语义类别：付款、紧急、保密、银行账户变更、并购、高管指令、泛称呼。
  # 这些特征只作为证据之一，永远不会单独决定拦截。
  class TextFeatures
    KEYWORDS = {
      payment: %w[付款 汇款 转账 定金 款项 费用 发票 报销 保证金 首付款 尾款 账户 打款 代付 垫付
                  wire payment transfer deposit invoice fund],
      urgency: %w[紧急 尽快 立刻 马上 今天 下班前 限时 速 抓紧 务必
                  urgent asap immediately quickly today],
      secrecy: %w[保密 不要告诉 勿告诉 私下 低调 暂时别 先别声张 仅限你我 不要回复
                  confidential secrecy keep.secret between.us do.not.reply],
      bank_change: %w[新账户 变更账户 账户变更 更换账户 修改收款 新的收款 收款信息更新 银行卡号
                      new.account bank.change change.account updated.accounting
                      new.payment.details account.details],
      mna: %w[并购 收购 尽调 交割 标的 保密协议 框架协议 增资 股权转让
              m&a acquisition merger due.diligence closing deal],
      authority: %w[我是 本人 授权 按我说 直接安排 不用走流程 特批 指令
                    authorize instruction on.my.behalf],
      generic_greeting: %w[亲爱的同事 尊敬的财务 财务同事 相关同事 各位财务 dear.finance team.dear
                           hello.there dear.accounts]
    }.freeze

    attr_reader :subject, :body

    def initialize(email)
      @subject = email.subject.to_s
      @body = email.body.to_s
      @text = "#{@subject}\n#{@body}".downcase
    end

    def present?(category)
      matched(category).any?
    end

    def matched(category)
      words = KEYWORDS.fetch(category, [])
      words.select { |w| @text.include?(w.downcase) }
    end

    def categories_present
      KEYWORDS.keys.select { |c| present?(c) }.reject { |c| c == :generic_greeting }
    end

    # BEC 经典语义组合：要求资金 + 制造紧迫 + 要求保密
    def bec_triad?
      present?(:payment) && present?(:urgency) && present?(:secrecy)
    end

    # 资金请求 + 银行账户变更是“改款诈骗”的最强语义信号
    def payment_with_bank_change?
      present?(:payment) && present?(:bank_change)
    end

    def payment_request?
      present?(:payment)
    end

    def generic_greeting?
      present?(:generic_greeting)
    end

    # 回复线程却突然换话题（难点3：被盗邮箱回复旧线程谈新的付款）
    def topic_shift?(email, thread_topic_keywords)
      thread_topic_keywords.none? { |kw| @text.include?(kw.downcase) }
    end

    def explain(category)
      hits = matched(category)
      return nil if hits.empty?
      label = CATEGORY_LABELS[category] || category.to_s
      "#{label}语义（命中：#{hits.first(3).join('、')}）"
    end

    CATEGORY_LABELS = {
      payment: "资金请求",
      urgency: "催促紧迫",
      secrecy: "要求保密",
      bank_change: "银行账户变更",
      mna: "并购交易",
      authority: "高管指令口吻",
      generic_greeting: "泛称呼"
    }.freeze
  end
end
