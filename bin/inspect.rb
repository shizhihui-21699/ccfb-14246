#!/usr/bin/env ruby
# frozen_string_literal: true

# 单封邮件检测演示：
#   ruby bin/inspect.rb '<发件地址>' '<显示名>' '<主题>' '<正文>' [线程ID]
# 例：
#   ruby bin/inspect.rb 'ceo.zhang@beichen-teoh.com' '张明远 CEO' '紧急付款' '请今天紧急汇款，保密'
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "bec_detector"

if ARGV.length < 4
  warn "用法: #{$PROGRAM_NAME} <发件地址> <显示名> <主题> <正文> [线程ID] [spf结果]"
  exit 1
end

from, display, subject, body, thread, spf = ARGV
email = BecDetector::Email.new(
  id: "manual-1", from_address: from, display_name: display,
  subject: subject, body: body, thread_id: thread,
  spf: (spf || "pass").to_sym, dkim: :pass, dmarc: (spf || "pass").to_sym
)

graph = BecDetector::IdentityGraph.build_default
verdict = BecDetector::Detector.new(graph).inspect(email)

action_label = { block: "⛔ 直接拦截", quarantine: "🔶 人工复核", allow: "✅ 放行" }[verdict.action]
puts "=" * 70
puts "发件人：#{verdict.email.display_name} <#{verdict.email.from_address}>"
puts "主  题：#{verdict.email.subject}"
puts "结  论：#{action_label}（证据总分 #{verdict.score}）"
verdict.policy_notes.each { |n| puts "策  略：#{n}" }
puts "-" * 70
puts "判定依据（按证据权重排序）："
verdict.signals.sort_by { |s| [-s.direction * s.score.abs, s.id] }.each do |s|
  mark = s.direction == 1 ? "＋#{s.score}" : "−#{s.score.abs}"
  puts "  [#{mark.to_s.ljust(4)}] [#{s.layer}] #{s.reason}"
end
puts "=" * 70
