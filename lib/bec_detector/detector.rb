# frozen_string_literal: true

module BecDetector
  # 单封邮件的检测结论
  class Verdict
    attr_reader :email, :action, :score, :signals, :policy_notes

    def initialize(email, action, score, signals, policy_notes)
      @email = email
      @action = action
      @score = score
      @signals = signals
      @policy_notes = policy_notes
    end

    def blocked?
      @action == :block
    end

    def quarantined?
      @action == :quarantine
    end

    def intercepted?
      blocked? || quarantined?
    end

    def reasons
      @signals.sort_by { |s| [-s.direction * s.score.abs, s.id] }.map(&:reason)
    end

    def top_reasons(n = 3)
      @signals.select { |s| s.direction == 1 }
              .sort_by { |s| -s.score }
              .first(n)
              .map(&:reason)
    end

    def to_h
      {
        id: email.id,
        from: email.from_address,
        display_name: email.display_name,
        action: action,
        score: score,
        label: email.label,
        scenario: email.scenario_name,
        reasons: reasons,
        policy_notes: policy_notes
      }
    end
  end

  # 检测器：汇总证据分 -> 应用策略规则 -> 给出 拦截/复核/放行 与解释。
  #
  # 阈值经数据集标定（见 README 的标定过程）：
  #   score >= BLOCK_THRESHOLD      => block（直接拦截，邮件不进员工收件箱）
  #   QUARANTINE..BLOCK-1           => quarantine（进人工复核队列，不直接送达）
  #   其余                          => allow（正常送达）
  class Detector
    BLOCK_THRESHOLD = 55
    QUARANTINE_THRESHOLD = 30

    def initialize(graph)
      @graph = graph
      @engine = SignalEngine.new(graph)
    end

    def inspect(email)
      signals = @engine.evaluate(email)
      raw_score = signals.sum(&:score)
      policy_notes = []

      score, override_action = apply_policies(email, signals, raw_score, policy_notes)
      action = override_action || decide(score)

      Verdict.new(email, action, score, signals, policy_notes)
    end

    private

    def decide(score)
      return :block if score >= BLOCK_THRESHOLD
      return :quarantine if score >= QUARANTINE_THRESHOLD

      :allow
    end

    # 策略层覆盖规则：处理“分数会撒谎”的边界情况
    def apply_policies(email, signals, score, notes)
      ids = signals.map(&:id)
      tf = TextFeatures.new(email)
      result_score = score

      # 规则P1：仿冒公司/合作方域名（S01/S02）+ 资金语义 = 确定性拦截，无视总分
      if (ids.include?(:S01) || ids.include?(:S02)) && tf.payment_request?
        notes << "P1 确定性规则：仿冒域名叠加资金请求，直接拦截"
        return [result_score, :block]
      end

      # 规则P2：SPF/DKIM/DMARC 认证失败 + 资金/账户变更语义 = 直接拦截
      if email.auth_failures.any? && (tf.payment_request? || tf.present?(:bank_change))
        notes << "P2 确定性规则：发件认证失败叠加资金/账户变更语义，直接拦截"
        return [result_score, :block]
      end

      # 规则P3（难点1保护）：高管登记过的私人邮箱别名，即使触发语义信号也不得直接拦截，
      # 封顶到复核档以下的上沿，避免把 CEO 用手机发的真邮件拦死
      emp = @graph.employee_by_email(email.from_address)
      if emp && email.from_domain != @graph.corp_domain
        if result_score >= BLOCK_THRESHOLD
          notes << "P3 别名保护：该地址是 #{emp.name} 登记过的私人邮箱，降为人工复核而非直接拦截"
          result_score = BLOCK_THRESHOLD - 1
        end
      end

      # 规则P4（难点2保护）：合作方仅“换新域、显示名一致、无任何资金/威胁信号”时不拦截，
      # 未知域的基础分已较低（S07=8），这里只做说明
      partner_named = signals.any? { |s| s.id == :S07 }
      if partner_named && !tf.payment_request? && !tf.present?(:bank_change) && email.auth_all_pass?
        notes << "P4 换域观察：疑似合作方更换邮箱且无资金异常，保持人工复核而非拦截"
      end

      [result_score, nil]
    end
  end
end
