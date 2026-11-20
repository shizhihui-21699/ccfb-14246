# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test" << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

desc "运行合成数据集评测，输出拦截率/误拦率"
task :evaluate do
  ruby "bin/evaluate.rb"
end

task default: :test
