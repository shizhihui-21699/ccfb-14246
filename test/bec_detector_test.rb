# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "minitest/autorun"
require "bec_detector"
require "dataset"

class BecDetectorTest < Minitest::Test
  def setup
    @graph = BecDetector::IdentityGraph.build_default
    @detector = BecDetector::Detector.new(@graph)
  end

  def v(email)
    @detector.inspect(email)
  end

  def em(**attrs)
    BecDetector::Email.new({ id: "t", spf: :pass, dkim: :pass, dmarc: :pass }.merge(attrs))
  end

  # ---------- 域名分析 ----------
  def test_one_letter_typo_detected
    r = BecDetector::DomainAnalyzer.new(@graph).analyze("ceo@beichen-teoh.com")
    assert r.lookalike?
    assert_equal :lookalike_corp, r.kind
  end

  def test_homoglyph_detected
    r = BecDetector::DomainAnalyzer.new(@graph).analyze("x@beichen-tech.c0m")
    assert r.lookalike?
  end

  def test_tld_swap_detected
    r = BecDetector::DomainAnalyzer.new(@graph).analyze("x@beichen-tech.net")
    assert r.lookalike?
  end

  def test_subdomain_abuse_detected
    r = BecDetector::DomainAnalyzer.new(@graph).analyze("x@beichen-tech.com.evil.cn")
    assert r.lookalike?
  end

  def test_unrelated_domain_not_flagged
    r = BecDetector::DomainAnalyzer.new(@graph).analyze("x@totally-different-xyz.com")
    refute r.lookalike?
    assert_equal :unknown, r.kind
  end

  def test_real_corp_and_partner_domains
    assert_equal :corp, BecDetector::DomainAnalyzer.new(@graph).analyze("x@beichen-tech.com").kind
    assert_equal :partner, BecDetector::DomainAnalyzer.new(@graph).analyze("x@hongyuan-supply.com").kind
  end

  # ---------- 难点1：高管私人邮箱 ----------
  def test_registered_private_alias_allowed
    verdict = v(em(from_address: "mingyuan.zhang@qq.com", display_name: "张明远",
                   subject: "手机发送", body: "周一并购例会材料看过了，按计划推进"))
    assert_equal :allow, verdict.action
  end

  def test_unregistered_freemail_impersonating_exec_blocked_or_quarantined
    verdict = v(em(from_address: "zhang.ceo123@gmail.com", display_name: "张明远 CEO",
                   subject: "紧急付款", body: "请今天立即转账一笔定金，注意保密，不要告诉别人"))
    assert verdict.intercepted?
    assert_includes verdict.reasons.join, "免费邮箱"
  end

  # ---------- 难点2：合作方换邮箱 ----------
  def test_partner_new_domain_no_money_quarantined_not_blocked
    verdict = v(em(from_address: "ap@hongyuan-group.com", display_name: "宏远供应商",
                   subject: "域名升级", body: "我司邮箱域名升级，本邮件仅作告知，无付款事项"))
    # 无资金异常的换域告知绝不允许直接拦截（放行或复核都可接受，由运营策略选）
    refute_equal :block, verdict.action
  end

  # ---------- 难点3：邮箱被盗，认证全过 ----------
  def test_compromised_partner_mailbox_caught_by_behavior
    verdict = v(em(from_address: "ap@hongyuan-supply.com", display_name: "宏远供应商",
                   subject: "回复：供货", thread_id: "TH-HY-01", in_reply_to: "m1",
                   body: "我司收款银行账户变更，请将后续款项尽快付至新账户"))
    assert verdict.intercepted?
    assert_includes verdict.reasons.join, "账户变更"
  end

  def test_real_account_change_with_process_not_flagged
    verdict = v(em(from_address: "ap@hongyuan-supply.com", display_name: "宏远供应商 财务部",
                   subject: "账户变更正式函", thread_id: "TH-HY-01",
                   body: "收款账户下月变更，正式变更函及银行证明见附件，请走供应商信息变更流程，电话确认后生效"))
    assert_equal :allow, verdict.action
  end

  def test_compromised_internal_mailbox_role_deviation
    verdict = v(em(from_address: "zhaox@beichen-tech.com", display_name: "赵雪 出纳",
                   subject: "紧急", thread_id: "TH-INTERNAL-02", in_reply_to: "m2",
                   body: "张总授权，请立即垫付保证金30万，不用走流程，事后补审批，注意保密"))
    assert verdict.intercepted?
  end

  # ---------- 正常流量不得误杀 ----------
  def test_normal_internal_mail
    verdict = v(em(from_address: "wangjg@beichen-tech.com", display_name: "王建国",
                   subject: "预算会议", body: "本周预算评审改到周四，请准备费用明细"))
    assert_equal :allow, verdict.action
  end

  def test_normal_urgent_payment_through_process
    verdict = v(em(from_address: "wangjg@beichen-tech.com", display_name: "王建国 财务经理",
                   subject: "紧急付款审批", thread_id: "TH-INTERNAL-01",
                   body: "这笔货款今天需支付，OA已提交，合同发票齐全，请按审批流程审核，账户为备案账户"))
    assert_equal :allow, verdict.action
  end

  def test_law_firm_confidential_mail
    verdict = v(em(from_address: "liu.ming@hengdalaw.com", display_name: "恒达律师事务所 刘明",
                   subject: "保密协议审查", thread_id: "TH-LAW-01",
                   body: "本邮件含保密信息，框架协议修改意见见附件，不涉及付款指令"))
    assert_equal :allow, verdict.action
  end

  # ---------- 解释性 ----------
  def test_verdict_explains_reasons
    verdict = v(em(from_address: "ceo@beichen-teoh.com", display_name: "张明远 CEO",
                   subject: "紧急并购定金", body: "请今天立即汇款，保密", spf: :fail, dmarc: :fail))
    assert verdict.blocked?
    assert(verdict.reasons.length >= 2)
    assert(verdict.top_reasons.first.include?("仿冒公司域名"))
  end

  # ---------- 全数据集指标回归 ----------
  def test_dataset_metrics
    mails = Dataset.build
    verdicts = mails.map { |m| @detector.inspect(m) }
    attacks = verdicts.select { |x| x.email.label == "attack" }
    benigns = verdicts.select { |x| x.email.label == "benign" }

    # 没有任何攻击邮件直接送达员工
    assert(attacks.all?(&:intercepted?), "存在漏网攻击邮件")
    # 正常邮件零硬误杀
    assert(benigns.none?(&:blocked?), "存在被直接拦截的正常邮件")
    # 人工复核打扰率控制在 5% 以内
    fp_rate = benigns.count(&:intercepted?).to_f / benigns.size
    assert(fp_rate <= 0.05, "复核打扰率过高: #{fp_rate}")
  end
end
