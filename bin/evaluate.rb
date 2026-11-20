#!/usr/bin/env ruby
# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "bec_detector"
require "dataset"

mails = Dataset.build
graph = BecDetector::IdentityGraph.build_default
detector = BecDetector::Detector.new(graph)
verdicts = mails.map { |m| detector.inspect(m) }

def pct(n, d)
  d.zero? ? 0.0 : (n.to_f / d * 100).round(2)
end

attacks   = verdicts.select { |v| v.email.label == "attack" }
benigns   = verdicts.select { |v| v.email.label == "benign" }

atk_block = attacks.count(&:blocked?)
atk_quar  = attacks.count(&:quarantined?)
atk_inter = attacks.count(&:intercepted?)
ben_block = benigns.count(&:blocked?)
ben_quar  = benigns.count(&:quarantined?)
ben_inter = benigns.count(&:intercepted?)

puts "=" * 78
puts "冒充高管/合作方邮件识别服务 —— 合成数据集评测报告"
puts "=" * 78
puts "数据集：攻击 #{attacks.size} 封 / 正常 #{benigns.size} 封，共 #{verdicts.size} 封"
puts "处置阈值：拦截 >= #{BecDetector::Detector::BLOCK_THRESHOLD} 分，" \
     "人工复核 >= #{BecDetector::Detector::QUARANTINE_THRESHOLD} 分，其余放行"
puts "-" * 78
puts "【核心指标】"
puts "拦截率（仅 block，攻击邮件被直接拦下的比例）：" \
     "  #{pct(atk_block, attacks.size)}% (#{atk_block}/#{attacks.size})"
puts "综合拦截率（block + quarantine，攻击邮件未直接送达员工的比例）：" \
     "#{pct(atk_inter, attacks.size)}% (#{atk_inter}/#{attacks.size})"
puts "误拦率（仅 block，正常邮件被错杀的比例）：" \
     "        #{pct(ben_block, benigns.size)}% (#{ben_block}/#{benigns.size})"
puts "综合误拦率（block + quarantine，正常邮件被人工打扰的比例）：" \
     "  #{pct(ben_inter, benigns.size)}% (#{ben_inter}/#{benigns.size})"
puts "-" * 78

def scenario_table(verdicts, label)
  puts "【#{label}侧分场景明细】"
  groups = verdicts.group_by { |v| v.email.scenario_name }
  puts format("%-26s %5s %6s %6s %6s %10s", "场景", "样本", "拦截", "复核", "放行", "拦截率%")
  groups.each do |name, vs|
    b = vs.count(&:blocked?)
    q = vs.count(&:quarantined?)
    a = vs.count { |v| v.action == :allow }
    puts format("%-26s %5d %6d %6d %6d %9.1f%%",
                name, vs.size, b, q, a, pct(b + q, vs.size))
  end
  puts "-" * 78
end

scenario_table(attacks, "攻击")
scenario_table(benigns, "正常")

# 被误拦/误复核的正常邮件逐条列出，说明误报来源
wrong = benigns.select(&:intercepted?)
unless wrong.empty?
  puts "【正常邮件被拦下/复核的逐条原因（误报审计）】"
  wrong.each do |v|
    puts "#{v.email.id} [#{v.action}|#{v.score}分] #{v.email.scenario_name} <- #{v.email.from_address}"
    v.top_reasons(2).each { |r| puts "    · #{r}" }
  end
  puts "-" * 78
end

# 漏网的攻击邮件
missed = attacks.reject(&:intercepted?)
unless missed.empty?
  puts "【漏网攻击邮件（直接送达员工）】"
  missed.each do |v|
    puts "#{v.email.id} [#{v.score}分] #{v.email.scenario_name} <- #{v.email.from_address}"
    v.top_reasons(2).each { |r| puts "    · #{r}" }
  end
  puts "-" * 78
end

# 分数分布，供阈值标定参考
puts "【分数分布（供阈值标定）】"
all_scores = verdicts.map(&:score).sort
puts "攻击邮件分数区间：#{attacks.map(&:score).min} ~ #{attacks.map(&:score).max}，" \
     "中位数 #{attacks.map(&:score).sort[attacks.size / 2]}"
puts "正常邮件分数区间：#{benigns.map(&:score).min} ~ #{benigns.map(&:score).max}，" \
     "中位数 #{benigns.map(&:score).sort[benigns.size / 2]}"
puts "-" * 78
puts "结论：直接拦截零误杀时的攻击拦截率 #{pct(atk_block, attacks.size)}%；" \
     "剩余风险由人工复核层兜底，综合处置率 #{pct(atk_inter, attacks.size)}%。"
