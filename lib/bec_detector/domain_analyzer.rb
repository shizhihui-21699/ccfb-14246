# frozen_string_literal: true

module BecDetector
  # 域名分析：判断发件域是公司域、合作方域、免费邮箱、未知域，还是某已知域的“仿冒域”。
  # 仿冒手法覆盖：同主体换后缀(TLD)、一字母之差(typosquat)、同形异义字/数字替换、
  # 把已知域降级为子域(subdomain abuse)、多写/漏写一个字符。
  class DomainAnalyzer
    FREE_MAIL_DOMAINS = %w[
      qq.com 163.com 126.com yeah.net foxmail.com gmail.com
      outlook.com hotmail.com live.com sina.com sohu.com aliyun.com
    ].freeze

    # 拉丁字母与数字的视觉/键盘近似映射
    HOMOGLYPH = {
      "0" => "o", "1" => "l", "3" => "e", "5" => "s", "rn" => "m",
      "l" => "i", "i" => "l"
    }.freeze

    Result = Struct.new(:kind, :target_name, :target_domain, :techniques, :distance,
                        keyword_init: true) do
      def lookalike?
        kind == :lookalike_corp || kind == :lookalike_partner
      end
    end

    def initialize(graph)
      @graph = graph
      @known = []
      @known << ["公司主域", graph.corp_domain, :lookalike_corp]
      graph.partners.each do |p|
        p.domains.each { |d| @known << [p.name, d, :lookalike_partner] }
      end
    end

    def analyze(address)
      domain = address.to_s.split("@", 2).last.to_s.downcase
      return Result.new(kind: :unknown, techniques: []) if domain.empty?

      return Result.new(kind: :corp, target_domain: domain, techniques: []) if domain == @graph.corp_domain
      if @graph.known_partner_domain?(domain)
        p = @graph.partner_by_domain(domain)
        return Result.new(kind: :partner, target_name: p&.name, target_domain: domain, techniques: [])
      end
      return Result.new(kind: :free_mail, target_domain: domain, techniques: []) if free_mail?(domain)

      # 子域滥用：beichen-tech.com.evil.com / beichen-tech.com.evil.net
      abuse = subdomain_abuse(domain)
      if abuse
        name, kind = abuse
        return Result.new(kind: kind, target_name: name, target_domain: domain,
                          techniques: ["子域滥用：把 #{known_label(kind)} 的域名嵌进自己的子域"], distance: 99)
      end

      # 与所有已知域做相似性比对
      best = nil
      @known.each do |name, known_d, kind|
        verdict = compare(registrable(domain), registrable(known_d))
        next if verdict.nil?
        candidate = Result.new(kind: kind, target_name: name, target_domain: known_d,
                               techniques: verdict[:techniques], distance: verdict[:distance])
        best = candidate if best.nil? || candidate.distance < best.distance
      end
      return best if best

      Result.new(kind: :unknown, target_domain: domain, techniques: [])
    end

    def free_mail?(domain)
      FREE_MAIL_DOMAINS.include?(registrable(domain))
    end

    # 比较两个“可注册主体”（已去掉子域和公共后缀的影响）
    def compare(dom_base, known_base)
      return nil if dom_base == known_base
      dom_sld, dom_tld = split_sld_tld(dom_base)
      known_sld, known_tld = split_sld_tld(known_base)

      techniques = []
      distance = levenshtein(dom_sld, known_sld)

      # 长度差太多就不是仿冒，避免误伤完全不相干的域
      return nil if (dom_sld.length - known_sld.length).abs > 2
      return nil if known_sld.length < 4

      if dom_sld == known_sld && dom_tld != known_tld
        techniques << "同主体换后缀：#{known_sld}.#{known_tld} → #{dom_sld}.#{dom_tld}"
        return { techniques: techniques, distance: 1 }
      end

      # 同形字/数字替换后相等
      if canonical(dom_sld) == canonical(known_sld)
        techniques << "同形/数字替换：#{dom_sld} 视觉上近似 #{known_sld}"
        return { techniques: techniques, distance: 1 }
      end

      if distance <= 2
        techniques << "一字母之差（编辑距离#{distance}）：#{known_sld} → #{dom_sld}"
        { techniques: techniques, distance: distance }
      end
    end

    def subdomain_abuse(domain)
      labels = domain.split(".")
      @known.each do |name, known_d, kind|
        known_labels = known_d.split(".")
        idx = labels.each_cons(known_labels.length).find_index { |seg| seg == known_labels }
        # 命中位置不是域名尾部（尾部就是真域了，前面已处理），即被当成子域标签
        if idx && idx + known_labels.length < labels.length
          return [name, kind]
        end
      end
      nil
    end

    def known_label(kind)
      kind == :lookalike_corp ? "公司" : "合作方"
    end

    # 取可注册主体：简化处理公共后缀，.com.cn/.net.cn/.org.cn 取三段，其余取两段
    def registrable(domain)
      parts = domain.split(".")
      return domain if parts.length <= 2
      if parts.last(2).join(".") =~ /\A(com|net|org|gov|edu)\.(cn|hk|tw)\z/
        parts.last(3).join(".")
      else
        parts.last(2).join(".")
      end
    end

    def split_sld_tld(base)
      parts = base.split(".")
      [parts[0..-2].join("."), parts[-1]]
    end

    # 视觉归一化：数字转形近字母、rn 合并、去掉连字符
    def canonical(sld)
      s = sld.tr("-", "")
      s = s.gsub("rn", "m")
      s.chars.map { |c| HOMOGLYPH[c] || c }.join
    end

    def levenshtein(a, b)
      a = a.downcase
      b = b.downcase
      row = (0..b.length).to_a
      a.each_char.with_index do |ca, i|
        cur = [i + 1]
        b.each_char.with_index do |cb, j|
          cost = ca == cb ? 0 : 1
          cur << [row[j + 1] + 1, cur[j] + 1, row[j] + cost].min
        end
        row = cur
      end
      row.last
    end
  end
end
