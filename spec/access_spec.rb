require File.dirname(__FILE__) + '/spec_helper'

module AccessModuleSpecHelper
  def request
    @request
  end

  def create_controller(&block)
    controller = Class.new(ApplicationController)
    controller.class_eval do
      %w(first second third).each do |word|
        class_eval <<-src_code, __FILE__, __LINE__
          def #{word}
            render :text => '#{word.capitalize}!'
          end
          def #{word}?
            action_name == '#{word}'
          end
          def not_#{word}?
            action_name != '#{word}'
          end
        src_code
      end
    end
    controller.class_eval(&block) if block
    @controller = controller.new
    controller
  end

  def create_sub_controller(&block)
    sub_controller = Class.new(@controller.class)
    sub_controller.class_eval(&block) if block
    @controller = sub_controller.new
    sub_controller
  end

  def pass_test(*actions)
    %w(first second third).each do |action|
      if actions.include?(action.to_sym) || actions == [:all] || actions == []
        send("#{action}_should_pass")
      else
        send("#{action}_should_not_pass")
      end
    end
  end

  def method_missing(method, *args, &block)
    if m = method.to_s.match(/^(first|second|third)_should(_not)?_pass$/)
      # first_should_pass, first_should_not_pass, second_should_pass, second_should_not_pass, third_should_pass, third_should_not_pass
      get m[1]
      unless m[2]
        @response.should have_text("#{m[1].camelize}!")
      else
        @response.should redirect_to('/')
      end
    else
      super(method, *args, &block)
    end
  end

end

describe Access do
  include AccessModuleSpecHelper
  before(:each) do
    @request    = ActionController::TestRequest.new
    @response   = ActionController::TestResponse.new
  end

  it "should allow without rules" do
    create_controller

    pass_test(:all)
  end

  it "should allow for global allow" do
    create_controller do
      allow
    end

    pass_test(:all)
  end

  it "should deny for global deny" do
    create_controller do
      deny
    end

    pass_test(:none)
  end

  it "should handle \"silly\" rules (example 1)" do
    create_controller do
      allow
      allow
      allow
    end

    pass_test(:all)
  end

  it "should handle \"silly\" rules (example 2)" do
    create_controller do
      allow
      deny
      allow
    end

    pass_test(:all)
  end

end

describe Access, 'with individual rules' do
  include AccessModuleSpecHelper
  before(:each) do
    @request    = ActionController::TestRequest.new
    @response   = ActionController::TestResponse.new
  end

  it "should allow all if allow rule applies only to one action" do
    create_controller do
      allow :first
    end

    pass_test(:all)
  end

  it "should deny only one action if deny rule applies only to that action" do
    create_controller do
      deny :first
    end

    pass_test(:second, :third)
  end

  it "should deny all if last rule is global deny" do
    create_controller do
      allow :first
      deny
    end

    pass_test(:none)
  end

  it "should allow only one action if rule allowing it goes after global deny" do
    create_controller do
      deny
      allow :first
    end

    pass_test(:first)
  end

  it "should handle multiple rules" do
    create_controller do
      deny :first
      deny :third
    end

    pass_test(:second)
  end

  it "should handle multiple actions per rule" do
    create_controller do
      deny :first, :third
    end

    pass_test(:second)
  end

  it "should handle long dumb list of rules" do
    create_controller do
      # + + +
      deny :first, :third
      # - + -
      allow :first, :second
      # + + -
      deny :second, :third
      # + - -
      allow :first, :third
      # + - +
      deny :first, :second
      # - - +
      allow :second, :third
      # - + +
    end

    pass_test(:second, :third)
  end

end

describe Access, 'with if and unless' do
  include AccessModuleSpecHelper
  before(:each) do
    @request    = ActionController::TestRequest.new
    @response   = ActionController::TestResponse.new
  end

  it "should apply rule if function evaluates to true" do
    create_controller do
      deny :if => :first?
    end
    pass_test(:second, :third)
  end

  it "should apply rule if inline block evaluates to true" do
    create_controller do
      deny :if => lambda{ |c| c.action_name == 'first' }
    end
    pass_test(:second, :third)
  end

  it "should apply rule if string evaluates to true" do
    create_controller do
      deny :if => "first? or second?"
    end
    pass_test(:third)
  end

  it "should apply rule if all evaluates to true" do
    create_controller do
      deny :if => [:not_first?, 'not_second?']
    end
    pass_test(:first, :second)
  end

  it "should apply rule unless function evaluates to true" do
    create_controller do
      deny :unless => :first?
    end
    pass_test(:first)
  end

  it "should apply rule if all in array evaluates to true" do
    create_controller do
      deny :if_all => [:not_first?, 'not_second?']
    end
    pass_test(:first, :second)
  end

  it "should apply rule if any in array evaluates to true" do
    create_controller do
      deny :if_any => [:first?, 'second?']
    end
    pass_test(:third)
  end

  it "should apply rule if all in array evaluates to true" do
    create_controller do
      deny :unless_all => [:not_first?, 'not_second?']
    end
    pass_test(:third)
  end
  
  it "should apply rule if any in array evaluates to true" do
    create_controller do
      deny :unless_any => [:first?, 'second?']
    end
    pass_test(:first, :second)
  end

end

describe Access, 'with default access' do
  include AccessModuleSpecHelper
  before(:each) do
    @request    = ActionController::TestRequest.new
    @response   = ActionController::TestResponse.new
  end

  it "should allow if allow_by_default" do
    create_controller do
      allow_by_default
    end

    pass_test(:all)
  end

  it "should deny if deny_by_default" do
    create_controller do
      deny_by_default
    end

    pass_test(:none)
  end

  it "should inherit allow_by_default" do
    create_controller do
      allow_by_default
    end
    create_sub_controller

    pass_test(:all)
  end

  it "should inherit deny_by_default" do
    create_controller do
      deny_by_default
    end
    create_sub_controller

    pass_test(:none)
  end

  it "should rewrite inherited allow_by_default" do
    create_controller do
      allow_by_default
    end
    create_sub_controller do
      deny_by_default
    end

    pass_test(:none)
  end

  it "should rewrite inherited deny_by_default" do
    create_controller do
      deny_by_default
    end
    create_sub_controller do
      allow_by_default
    end

    pass_test(:all)
  end

end
