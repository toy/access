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
      get action
      if actions.include?(action.to_sym) || actions == [:all]
        @response.should have_text("#{action.camelize}!")
        @response.should_not redirect_to('/')
      else
        @response.should_not have_text("#{action.camelize}!")
        @response.should redirect_to('/')
      end
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

  it "should allow for global allow after global deny" do
    create_controller do
      deny
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

  it "should deny for global deny after global allow" do
    create_controller do
      allow
      deny
    end
    pass_test(:none)
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
      deny :if => proc{ action_name == 'first' }
    end
    pass_test(:second, :third)
  end

  it "should apply rule if string evaluates to true" do
    create_controller do
      deny :if => "first? || second?"
    end
    pass_test(:third)
  end

  it "should apply rule unless function evaluates to true" do
    create_controller do
      deny :unless => :first?
    end
    pass_test(:first)
  end

  it "should apply rule if all expressions in any of inner arrays evaluases to true" do
    create_controller do
      deny :if => [[:first?, :not_second?], [:second?, :not_first?], [:third?, [:not_first?, :not_second?, :not_third?]]]
    end
    pass_test(:third)
  end

  it "should apply rule if any in array evaluates to true" do
    create_controller do
      deny :if => [:first?, :second?]
    end
    pass_test(:third)
  end
  
  it "should apply rule if all in array evaluates to true" do
    create_controller do
      deny :if_all => [:not_first?, :not_second?]
    end
    pass_test(:first, :second)
  end
  
  it "should apply rule if any in array evaluates to true" do
    create_controller do
      deny :unless => [:first?, :second?]
    end
    pass_test(:first, :second)
  end
  
  it "should apply rule if all in array evaluates to true" do
    create_controller do
      deny :unless_all => [:not_first?, :not_second?]
    end
    pass_test(:third)
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
