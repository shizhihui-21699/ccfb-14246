# frozen_string_literal: true

require_relative "bec_detector/email"
require_relative "bec_detector/identity_graph"
require_relative "bec_detector/domain_analyzer"
require_relative "bec_detector/text_features"
require_relative "bec_detector/signal_engine"
require_relative "bec_detector/detector"

# 冒充高管/合作方邮件识别服务（BEC, Business Email Compromise）
#
# 入口：
#   graph   = BecDetector::IdentityGraph.build_default
#   detector = BecDetector::Detector.new(graph)
#   result   = detector.inspect(email)
#   result.action   # :block | :quarantine | :allow
#   result.score    # 证据加权总分
#   result.reasons  # 每条证据的中文解释
module BecDetector
  VERSION = "1.0.0"
end
