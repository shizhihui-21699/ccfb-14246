# frozen_string_literal: true

module BecDetector
  # 身份图谱：公司掌握的“谁是谁、谁用什么邮箱、谁和谁有往来”的基线知识。
  # 检测质量的上限由这份基线决定，生产环境应从 HR / 邮件网关日志 / CRM 同步。
  class IdentityGraph
    TITLES = %w[总 经理 总监 总裁 董事长].freeze
    # 员工：name 中文名、pinyin 用于匹配本地部分、role 级别、
    # known_emails 含公司邮箱与登记过的私人别名（难点1：高管也会用手机/私人邮箱）
    Employee = Struct.new(:name, :pinyin, :role, :known_emails, keyword_init: true)
    # 合作方：name 名称、domains 历史已知域（难点2：合作方会换域，换域不等于旧域是假的）、
    # contact_emails 联系人邮箱、payment_capable 是否有过付款类往来
    Partner  = Struct.new(:name, :domains, :contact_emails, :payment_capable, keyword_init: true)

    attr_reader :corp_domain, :employees, :partners, :history, :address_book

    def initialize(corp_domain:, employees:, partners:, history:, address_book:)
      @corp_domain = corp_domain
      @employees = employees
      @partners = partners
      # history: 线程ID -> 该线程上出现过的发件地址数组（按时间顺序）
      @history = history
      # address_book: 地址 -> 显示名（全公司历史通信中出现过的可信通讯录）
      @address_book = address_book
    end

    def employee_by_email(addr)
      return nil if addr.nil?
      a = addr.downcase
      @employees.find { |e| e.known_emails.map(&:downcase).include?(a) }
    end

    def employee_by_name(name)
      return nil if name.nil?
      @employees.find { |e| e.name == name }
    end

    # 任意员工（按中文名或拼音/本地部分模糊），用于“冒充内部某人”的身份识别
    def match_employee_by_display(name)
      return nil if name.nil? || name.empty?
      exact = @employees.find { |e| e.name == name }
      return exact if exact
      contained = @employees.find { |e| name.include?(e.name) || e.name.include?(name) }
      return contained if contained
      # “张总/李总/王经理”这类姓氏+职务称呼
      if name.length >= 2
        surname = name[0]
        if TITLES.any? { |t| name.include?(t) }
          return @employees.find { |e| e.name.start_with?(surname) }
        end
      end
      nil
    end

    def known_corp_address?(addr)
      !employee_by_email(addr).nil?
    end

    def known_partner_domain?(domain)
      return false if domain.nil?
      d = domain.downcase
      @partners.any? { |p| p.domains.include?(d) }
    end

    def known_partner_address?(addr)
      return false if addr.nil?
      a = addr.downcase
      @partners.any? { |p| p.contact_emails.map(&:downcase).include?(a) }
    end

    def partner_by_domain(domain)
      return nil if domain.nil?
      @partners.find { |p| p.domains.include?(domain.downcase) }
    end

    def partner_by_name(name)
      return nil if name.nil?
      @partners.find { |p| p.name == name || name.include?(p.name) || p.name.include?(name) }
    end

    # 该地址是否在历史线程上出现过（难点3：被盗邮箱会出现在已有线程里，所以“出现过”只算弱信任）
    def seen_on_thread?(thread_id, addr)
      return false if thread_id.nil? || addr.nil?
      (@history[thread_id] || []).map(&:downcase).include?(addr.downcase)
    end

    def thread_participants(thread_id)
      (@history[thread_id] || []).map(&:downcase).uniq
    end

    def in_address_book?(addr)
      @address_book.key?(addr.to_s.downcase)
    end

    # ---------- 演示用基线：一家虚构的“北辰科技集团” ----------
    def self.build_default
      employees = [
        Employee.new(name: "张明远", pinyin: "zhangmingyuan", role: "CEO",
                     known_emails: %w[zhangmy@beichen-tech.com mingyuan.zhang@qq.com]),
        Employee.new(name: "李婉清", pinyin: "liwanqing", role: "CFO",
                     known_emails: %w[liwq@beichen-tech.com wanqing.li@163.com]),
        Employee.new(name: "王建国", pinyin: "wangjianguo", role: "财务经理",
                     known_emails: %w[wangjg@beichen-tech.com]),
        Employee.new(name: "赵雪",   pinyin: "zhaoxue", role: "出纳",
                     known_emails: %w[zhaox@beichen-tech.com]),
        Employee.new(name: "陈志强", pinyin: "chenzhiqiang", role: "采购总监",
                     known_emails: %w[chenzq@beichen-tech.com]),
        Employee.new(name: "孙婷",   pinyin: "sunting", role: "法务总监",
                     known_emails: %w[sunt@beichen-tech.com]),
        Employee.new(name: "周凯",   pinyin: "zhoukai", role: "IT经理",
                     known_emails: %w[zhouk@beichen-tech.com]),
        Employee.new(name: "吴芳",   pinyin: "wufang", role: "HR经理",
                     known_emails: %w[wuf@beichen-tech.com]),
        Employee.new(name: "郑海",   pinyin: "zhenghai", role: "普通员工",
                     known_emails: %w[zhengh@beichen-tech.com])
      ]

      partners = [
        Partner.new(name: "恒达律师事务所", domains: %w[hengdalaw.com],
                    contact_emails: %w[liu.ming@hengdalaw.com], payment_capable: false),
        Partner.new(name: "金诚会计师事务所", domains: %w[jinchengcpa.com],
                    contact_emails: %w[audit@jinchengcpa.com], payment_capable: false),
        Partner.new(name: "宏远供应商", domains: %w[hongyuan-supply.com],
                    contact_emails: %w[ap@hongyuan-supply.com sales.li@hongyuan-supply.com],
                    payment_capable: true),
        Partner.new(name: "蓝海并购顾问", domains: %w[blueocean-ma.com],
                    contact_emails: %w[deal@blueocean-ma.com], payment_capable: true),
        Partner.new(name: "启明客户公司", domains: %w[qiming-group.com],
                    contact_emails: %w[finance@qiming-group.com], payment_capable: true)
      ]

      history = build_history
      address_book = build_address_book(employees, partners, history)
      new(corp_domain: "beichen-tech.com", employees: employees, partners: partners,
          history: history, address_book: address_book)
    end

    def self.build_history
      {
        "TH-HY-01" => %w[ap@hongyuan-supply.com chenzq@beichen-tech.com wangjg@beichen-tech.com],
        "TH-HY-02" => %w[sales.li@hongyuan-supply.com chenzq@beichen-tech.com],
        "TH-BO-01" => %w[deal@blueocean-ma.com zhangmy@beichen-tech.com liwq@beichen-tech.com],
        "TH-QM-01" => %w[finance@qiming-group.com wangjg@beichen-tech.com],
        "TH-LAW-01" => %w[liu.ming@hengdalaw.com sunt@beichen-tech.com],
        "TH-AUDIT" => %w[audit@jinchengcpa.com liwq@beichen-tech.com],
        "TH-INTERNAL-01" => %w[zhangmy@beichen-tech.com wangjg@beichen-tech.com zhaox@beichen-tech.com],
        "TH-INTERNAL-02" => %w[liwq@beichen-tech.com zhaox@beichen-tech.com]
      }
    end

    def self.build_address_book(employees, partners, history)
      book = {}
      employees.each { |e| e.known_emails.each { |a| book[a.downcase] = e.name } }
      partners.each do |p|
        p.contact_emails.each { |a| book[a.downcase] = p.name }
      end
      history.each_value do |addrs|
        addrs.each { |a| book[a.downcase] ||= "历史联系人" }
      end
      book
    end
  end
end
