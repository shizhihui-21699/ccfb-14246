# frozen_string_literal: true

require_relative "bec_detector"

# 可复现的伪随机数发生器（不依赖 Random 的平台实现，保证每次运行数据集完全一致）
class LCG
  def initialize(seed = 20261121)
    @state = seed
  end

  def next!
    @state = (@state * 1_103_515_245 + 12_345) % (2**31)
    @state
  end

  def rand(n)
    next! % n
  end

  def pick(arr)
    arr[rand(arr.length)]
  end
end

# 合成数据集：320 封带标签邮件（150 攻击 / 170 正常），
# 攻击侧 10 个场景覆盖 BEC 常见手法与题目四个难点，
# 正常侧 10 个场景专门制造“看起来也很可疑”的误报陷阱。
module Dataset
  module_function

  def build
    @rng = LCG.new
    @seq = 0
    mails = []
    ATTACK_SCENARIOS.each { |s| mails.concat(s.call) }
    BENIGN_SCENARIOS.each { |s| mails.concat(s.call) }
    mails
  end

  def nid(prefix)
    @seq += 1
    "#{prefix}-#{@seq.to_s.rjust(3, '0')}"
  end

  def mail(attrs)
    base = {
      id: nid(attrs[:label] == "attack" ? "ATK" : "BEN"),
      spf: :pass, dkim: :pass, dmarc: :pass,
      to_list: ["finance@beichen-tech.com"], cc_list: [],
      has_attachment: false, has_link: false,
      in_reply_to: nil, thread_id: nil, reply_to: nil,
      sent_at: "2026-#{(@rng.rand(10) + 1).to_s.rjust(2, '0')}-#{(@rng.rand(27) + 1).to_s.rjust(2, '0')} 09:#{@rng.rand(59).to_s.rjust(2, '0')}"
    }
    BecDetector::Email.new(base.merge(attrs))
  end

  # ---------------- 攻击场景（10 类，共 150 封） ----------------

  ATTACK_SCENARIOS = [
    # A1 一字母之差仿冒公司域（题面案例）
    -> do
      bodies = [
        "紧急：并购项目需要立即支付一笔定金，请今天下班前安排汇款，注意保密，暂不要对外透露。附件是收款账户信息。",
        "有一笔并购保证金需要加急处理，请尽快安排转账，此事仅限财务核心人员知道，不要回复本邮件确认细节。",
        "请立即处理这笔首付款，对方催得很紧，今天必须到账。账号见附件，全程保密。"
      ]
      Array.new(18) do |i|
        d = ["beichen-teoh.com", "beichen-techh.com", "beicher-tech.com", "beichen-tec.com"][i % 4]
        mail(label: "attack", scenario_id: "A1", scenario_name: "一字母之差仿冒公司域",
             from_address: "ceo.zhang@#{d}", display_name: "张明远 CEO",
             subject: ["紧急：并购定金支付", "请加急处理保证金", "机密-付款安排"][i % 3],
             body: bodies[i % bodies.length], has_attachment: i.even?,
             spf: :fail, dmarc: :fail)
      end
    end,

    # A2 同形字/数字替换仿冒
    -> do
      Array.new(12) do |i|
        d = ["beichen-tech.c0m", "beichen-te5ch.com", "beichen-te1ch.com", "beichem-tech.com"][i % 4]
        mail(label: "attack", scenario_id: "A2", scenario_name: "同形字数字替换仿冒",
             from_address: "liwq@#{d}", display_name: "李婉清 CFO",
             subject: "账户变更通知（紧急）",
             body: "请将宏远供应商的后续付款改付到新账户，银行账户变更信息如下，本周发票先按新账号打款，尽快处理。",
             spf: i.even? ? :fail : :pass,
             dmarc: i.even? ? :fail : :none)
      end
    end,

    # A3 换后缀（TLD 仿冒）
    -> do
      Array.new(12) do |i|
        d = ["beichen-tech.net", "beichen-tech.org", "beichen-tech.hk"][i % 3]
        mail(label: "attack", scenario_id: "A3", scenario_name: "同主体换后缀仿冒",
             from_address: "zhangmy@#{d}", display_name: "张明远",
             subject: "保密项目用款",
             body: "我在外面开会，有笔保密的尽调费用需要你马上垫付，金额38万，今天下班前转账，先别告诉其他人，回来我补流程。",
             reply_to: "zhangmy.private@gmail.com")
      end
    end,

    # A4 子域滥用
    -> do
      Array.new(10) do |i|
        d = ["beichen-tech.com.secure-login.net", "mail.beichen-tech.com.evil.cn"][i % 2]
        mail(label: "attack", scenario_id: "A4", scenario_name: "子域滥用仿冒",
             from_address: "it.support@#{d}", display_name: "周凯 IT经理",
             subject: "邮箱系统升级验证",
             body: "亲爱的同事，邮箱系统即将升级，请点击链接重新验证登录信息，限时今天完成。",
             has_link: true, spf: :none, dmarc: :none)
      end
    end,

    # A5 免费邮箱+高管显示名（未登记私人邮箱）——难点1的攻击面
    -> do
      bodies = [
        "我是张明远，手机发的。有笔并购定金需要紧急安排，麻烦今天先转账，合同后补，注意保密。",
        "用私人邮箱联系你，公司邮箱暂时登不上。请立即支付一笔款项到指定账户，不要走常规审批，特批。",
        "紧急，我在出差。请财务马上安排一笔保密汇款，账号我私信发你，收到请直接处理。"
      ]
      Array.new(18) do |i|
        addr = ["zhangmingyuan.ceo@gmail.com", "zhangmy.1980@163.com",
                "beichen.ceo@qq.com", "mingyuan.zhang@sina.com"][i % 4]
        mail(label: "attack", scenario_id: "A5", scenario_name: "免费邮箱冒充高管",
             from_address: addr,
             display_name: ["张明远", "张明远 CEO", "张总"][i % 3],
             subject: ["紧急付款", "机密事项", "请立即处理"][i % 3],
             body: bodies[i % bodies.length])
      end
    end,

    # A6 免费邮箱冒充合作方
    -> do
      Array.new(12) do |i|
        mail(label: "attack", scenario_id: "A6", scenario_name: "免费邮箱冒充合作方",
             from_address: "hongyuan.ap.2026@gmail.com",
             display_name: "宏远供应商 财务部",
             subject: "收款账户变更通知",
             body: "我司银行账户变更，请将本月货款付至新账户，新的收款信息见附件，请尽快安排打款，避免影响发货。",
             has_attachment: true)
      end
    end,

    # A7 仿冒合作方域
    -> do
      Array.new(14) do |i|
        d = ["hongyuan-suplly.com", "hongyuansupply.com", "blueocean-ma.co", "qiming-gruop.com"][i % 4]
        name = { "hongyuan-suplly.com" => "宏远供应商", "hongyuansupply.com" => "宏远供应商",
                 "blueocean-ma.co" => "蓝海并购顾问", "qiming-gruop.com" => "启明客户公司" }[d]
        mail(label: "attack", scenario_id: "A7", scenario_name: "仿冒合作方域名",
             from_address: "ap@#{d}", display_name: "#{name} 财务",
             subject: "紧急：收款信息更新",
             body: "因我司银行系统升级，收款账户已变更，请将尾款转账至新账户，今日内完成，谢谢配合。",
             spf: i.even? ? :pass : :fail)
      end
    end,

    # A8 陌生地址入侵已有线程（难点3变体：攻击者用新域名回复真线程）
    -> do
      Array.new(14) do |i|
        mail(label: "attack", scenario_id: "A8", scenario_name: "陌生地址入侵往来线程",
             from_address: "ap.hongyuan@protonmail.com", display_name: "宏远供应商",
             subject: "回复：订单确认",
             body: "补充一下，这单的收款账户有变更，请安排定金时转到新账号，紧急，今天需要到账。",
             thread_id: "TH-HY-01", in_reply_to: "msg-#{900 + i}",
             has_attachment: i.even?)
      end
    end,

    # A9 合作方/内部邮箱真的被盗，SPF/DKIM 全过，回复真实线程——难点3本体
    -> do
      Array.new(14) do |i|
        if i < 8
          # 合作方邮箱被盗：认证全过、地址在线程里出现过
          mail(label: "attack", scenario_id: "A9", scenario_name: "邮箱被盗回复真实线程",
               from_address: "ap@hongyuan-supply.com", display_name: "宏远供应商 应收会计",
               subject: "回复：供货合同进度",
               body: "谢谢贵司支持。另外通知一下，我司收款银行账户变更，后续款项请付新账户，麻烦尽快处理本月货款。",
               thread_id: "TH-HY-01", in_reply_to: "msg-#{1000 + i}")
        else
          # 内部邮箱被盗：出纳的号发指令（角色偏离）
          mail(label: "attack", scenario_id: "A9", scenario_name: "内部邮箱被盗角色偏离",
               from_address: "zhaox@beichen-tech.com", display_name: "赵雪 出纳",
               subject: "紧急付款安排",
               body: "张总刚电话授权，请立即向该账户垫付一笔保证金30万，不用走流程，事后补审批，注意保密。",
               thread_id: "TH-INTERNAL-02", in_reply_to: "msg-#{1100 + i}")
        end
      end
    end,

    # A10 未知域冒充合作方新邮箱（换域名骗局）——与正常 B7 难分，靠语义区分
    -> do
      Array.new(12) do |i|
        mail(label: "attack", scenario_id: "A10", scenario_name: "未知域冒充合作方新邮箱",
             from_address: "finance@hongyuan-holdings.cn", display_name: "宏远供应商",
             subject: "公司更名及账户变更",
             body: "我司集团重组更名，这是新财务邮箱。现有货款请汇至新银行账户，附件为变更证明，请尽快安排付款。",
             has_attachment: true,
             spf: :pass, dkim: :pass, dmarc: :none)
      end
    end
  ].freeze

  # ---------------- 正常场景（10 类，共 170 封，含大量误报陷阱） ----------------

  BENIGN_SCENARIOS = [
    # B1 公司域内部常规邮件
    -> do
      Array.new(24) do |i|
        sender = [["zhangmy@beichen-tech.com", "张明远"], ["liwq@beichen-tech.com", "李婉清"],
                  ["wangjg@beichen-tech.com", "王建国"], ["chenzq@beichen-tech.com", "陈志强"]][i % 4]
        bodies = [
          "本周预算评审会议改到周四上午，请各位提前准备好费用明细。",
          "附上季度财务报表草稿，大家看一下有没有需要调整的地方。",
          "采购申请单已经审批通过，按正常流程走即可。",
          "下季度的部门预算请在周五前提交，模板在共享盘。"
        ]
        mail(label: "benign", scenario_id: "B1", scenario_name: "公司域内部常规邮件",
             from_address: sender[0], display_name: sender[1],
             subject: "内部工作安排", body: bodies[i % 4],
             thread_id: i.even? ? "TH-INTERNAL-01" : nil,
             has_attachment: i % 3 == 0)
      end
    end,

    # B2 合作方正常业务往来（已知域、登记地址、历史线程）
    -> do
      Array.new(22) do |i|
        sender = [["ap@hongyuan-supply.com", "宏远供应商"], ["sales.li@hongyuan-supply.com", "宏远供应商"],
                  ["deal@blueocean-ma.com", "蓝海并购顾问"], ["finance@qiming-group.com", "启明客户公司"]][i % 4]
        bodies = [
          "关于订单HY-2026的交货安排，预计下周三送达，请确认收货地址。",
          "本月对账单已出，金额与合同一致，请核对后回传盖章件。",
          "尽调资料清单见附件，麻烦提供对应财务底稿，谢谢。",
          "发票已按原账户信息开具，如有疑问随时联系。"
        ]
        mail(label: "benign", scenario_id: "B2", scenario_name: "合作方正常业务往来",
             from_address: sender[0], display_name: sender[1],
             subject: "业务往来", body: bodies[i % 4],
             thread_id: ["TH-HY-01", "TH-HY-02", "TH-BO-01", "TH-QM-01"][i % 4],
             in_reply_to: "msg-#{i}", has_attachment: i.even?)
      end
    end,

    # B3 合作方真实的账户变更（已知域、走流程措辞）——语义陷阱
    -> do
      Array.new(12) do |i|
        mail(label: "benign", scenario_id: "B3", scenario_name: "合作方真实账户变更",
             from_address: "ap@hongyuan-supply.com", display_name: "宏远供应商 财务部",
             subject: "关于我司收款账户变更的正式函",
             body: "我司因开户行调整，收款账户将于下月变更，正式变更函及银行证明见附件，" \
                   "请走贵司供应商信息变更流程，经双方财务电话确认后再生效，本月已开发票仍按原账户结算。",
             thread_id: "TH-HY-01", has_attachment: true)
      end
    end,

    # B4 合作方换域名（真实）——难点2
    -> do
      Array.new(14) do |i|
        mail(label: "benign", scenario_id: "B4", scenario_name: "合作方更换域名",
             from_address: "ap@hongyuan-group.com", display_name: "宏远供应商",
             subject: "我司域名升级通知",
             body: "因公司品牌升级，我司邮箱域名由 hongyuan-supply.com 升级为 hongyuan-group.com，" \
                   "合同主体不变，后续往来请使用新邮箱，原邮箱本月底停用。本邮件仅作告知，无付款事项。",
             spf: :pass, dkim: :pass, dmarc: :pass)
      end
    end,

    # B5 高管用登记过的私人邮箱/手机发信——难点1（含谈付款、并购、紧急的陷阱）
    -> do
      bodies = [
        "我在高铁上，手机发一下：下周一并购例会的材料我看过了，没问题，按原计划推进。",
        "周末临时想到，Q3 的费用预算偏紧，周一上午我们碰一下怎么调，不用急着今天处理。",
        "请财务帮我走一下我出差垫付的报销，发票在助理那里，按正常报销流程来。",
        "并购尽调的事我知道了，让法务先看协议，付款部分等我回公司签字后再走审批。"
      ]
      Array.new(16) do |i|
        addr = i.even? ? "mingyuan.zhang@qq.com" : "wanqing.li@163.com"
        name = i.even? ? "张明远" : "李婉清"
        mail(label: "benign", scenario_id: "B5", scenario_name: "高管登记私人邮箱发信",
             from_address: addr, display_name: name,
             subject: ["手机发送", "工作安排", "报销事项", "并购进展"][i % 4],
             body: bodies[i % 4])
      end
    end,

    # B6 正常紧急付款（公司域+流程措辞）
    -> do
      Array.new(14) do |i|
        mail(label: "benign", scenario_id: "B6", scenario_name: "正常紧急付款审批",
             from_address: "wangjg@beichen-tech.com", display_name: "王建国 财务经理",
             subject: "紧急付款审批：供应商货款",
             body: "这笔供应商货款需要今天支付以避免违约金，付款申请单已在OA提交，" \
                   "合同、发票和验收单齐全，请按付款审批流程尽快审核，账户为供应商原备案账户。",
             thread_id: "TH-INTERNAL-01")
      end
    end,

    # B7 法务/审计类敏感但正常的邮件
    -> do
      Array.new(14) do |i|
        sender = i.even? ? ["liu.ming@hengdalaw.com", "恒达律师事务所 刘明"] :
                           ["audit@jinchengcpa.com", "金诚会计师事务所"]
        mail(label: "benign", scenario_id: "B7", scenario_name: "法务审计敏感邮件",
             from_address: sender[0], display_name: sender[1],
             subject: "保密：协议审查/审计资料",
             body: "本邮件及附件含保密信息，请仅限项目组成员查阅。并购框架协议的修改意见见附件，" \
                   "其中不涉及任何付款指令，请按法务流程流转。",
             thread_id: i.even? ? "TH-LAW-01" : "TH-AUDIT",
             has_attachment: true)
      end
    end,

    # B8 陌生供应商冷销售（无资金请求）
    -> do
      Array.new(14) do |i|
        mail(label: "benign", scenario_id: "B8", scenario_name: "陌生供应商冷销售",
             from_address: "sales@newvendor-#{i}.top", display_name: "新锐办公设备 销售",
             subject: "办公设备供应合作意向",
             body: "您好，我司主营办公设备与耗材，希望能参与贵司采购比价，附产品目录供参考，如有意向再联系。",
             has_attachment: true, dmarc: :none)
      end
    end,

    # B9 内部带附件/链接的正常邮件
    -> do
      Array.new(14) do |i|
        mail(label: "benign", scenario_id: "B9", scenario_name: "内部附件链接邮件",
             from_address: "zhouk@beichen-tech.com", display_name: "周凯 IT经理",
             subject: "系统升级通知",
             body: "本周五晚邮件系统例行维护，内网访问地址为公司IT门户，请按指引完成客户端配置，无需回复密码信息。",
             has_link: true, thread_id: "TH-INTERNAL-01")
      end
    end,

    # B10 高管从公司域发出的真实指令（含付款审批、保密要求）——权重陷阱
    -> do
      Array.new(14) do |i|
        mail(label: "benign", scenario_id: "B10", scenario_name: "高管公司域真实指令",
             from_address: "zhangmy@beichen-tech.com", display_name: "张明远 CEO",
             subject: "并购项目付款审批",
             body: "蓝海并购顾问的第二期服务费可以安排支付，金额与框架协议一致，" \
                   "请财务核对合同节点后走正常审批，付款信息以CRM备案为准。该项目目前请保密。",
             thread_id: "TH-BO-01")
      end
    end,

    # B11 高管临时用未登记的新私人邮箱（真实但系统不知道）——必然进复核的灰色样本
    -> do
      Array.new(5) do |i|
        mail(label: "benign", scenario_id: "B11", scenario_name: "高管未登记新私人邮箱",
             from_address: "zhangmy.work@outlook.com", display_name: "张明远",
             subject: "手机临时发：周一会议材料",
             body: "我手机上公司邮箱没配好，先用这个邮箱。周一并购例会的材料我看过了，按原计划推进，付款的事回公司走流程。")
      end
    end,

    # B12 合作方换域后第一次发来带对账/付款字样的邮件（真实换域，语义踩线）
    -> do
      Array.new(5) do |i|
        mail(label: "benign", scenario_id: "B12", scenario_name: "合作方新域首次谈款",
             from_address: "ar@hongyuan-group.com", display_name: "宏远供应商 应收会计",
             subject: "新域名通知及本月对账",
             body: "我司已启用新域名 hongyuan-group.com，本月对账单请查收，金额请按合同核对，" \
                   "付款仍走原备案账户，账户无变更，附件为对账单。",
             has_attachment: true)
      end
    end,

    # B13 新员工入职第一封邮件（系统尚未同步其身份，措辞略带紧迫感）
    -> do
      Array.new(5) do |i|
        mail(label: "benign", scenario_id: "B13", scenario_name: "新员工首封邮件",
             from_address: "linhao@beichen-tech.com", display_name: "林浩 财务专员",
             subject: "入职资料及紧急报销",
             body: "大家好我是新入职的财务专员林浩，HR系统还在开通。有一笔差旅报销今天截止提交，麻烦指导一下流程，谢谢。")
      end
    end
  ].freeze
end
