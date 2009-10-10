require File.dirname(__FILE__) + '/spec_helper'

module AccessControllerCreator
  def create_controller(&block)
    Class.new(ApplicationController).tap do |controller|
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
    end
  end

  def test_controller(description, *blocks, &test_block)
    describe '' do
      controller = blocks.inject(nil) do |parent, block|
        if parent
          Class.new(parent).tap do |sub_controller|
            sub_controller.class_eval(&block) if block
          end
        else
          create_controller(&block)
        end
      end
      tests controller
      it description do
        self.instance_eval(&test_block)
      end
    end
  end
end

describe Access, :type => :controller do
  extend AccessControllerCreator
  def self.test_access(description, actions, *blocks)
    test_controller description, *blocks do
      actions = Array(actions)
      %w(first second third).each do |action|
        get action
        if actions == [:all] || actions.include?(action.to_sym)
          response.should have_text("#{action.camelize}!")
          response.should_not redirect_to('/')
        else
          response.should_not have_text("#{action.camelize}!")
          response.should redirect_to('/')
        end
      end
    end
  end

  test_access "should allow without rules", :all, proc{}

  test_access "should allow for global allow", :all, proc{
    allow
  }

  test_access "should allow for global allow after global deny", :all, proc{
    deny
    allow
  }

  test_access "should deny for global deny", :none, proc{
    deny
  }

  test_access "should deny for global deny after global allow", :none, proc{
    allow
    deny
  }

  describe "with individual rules" do
    test_access "should allow all if allow rule applies only to one action", :all, proc{
      allow :first
    }

    test_access "should deny only one action if deny rule applies only to that action", [:second, :third], proc{
      deny :first
    }

    test_access "should deny all if last rule is global deny", :none, proc{
      allow :first
      deny
    }

    test_access "should allow only one action if rule allowing it goes after global deny", :first, proc{
      deny
      allow :first
    }

    test_access "should handle multiple rules", :second, proc{
      deny :first
      deny :third
    }

    test_access "should handle multiple actions per rule", :second, proc{
      deny :first, :third
    }

    test_access "should handle long dumb list of rules", [:second, :third], proc{
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
    }
  end

  describe "with if and unless" do
    test_access "should apply rule if function evaluates to true", [:second, :third], proc{
      deny :if => :first?
    }

    test_access "should apply rule if inline block evaluates to true", [:second, :third], proc{
      deny :if => proc{ action_name == 'first' }
    }

    test_access "should apply rule if string evaluates to true", :third, proc{
      deny :if => "first? || second?"
    }

    test_access "should apply rule unless function evaluates to true", :first, proc{
      deny :unless => :first?
    }

    test_access "should apply rule if all expressions in any of inner arrays evaluases to true", :third, proc{
      deny :if => [[:first?, :not_second?], [:second?, :not_first?], [:third?, [:not_first?, :not_second?, :not_third?]]]
    }

    test_access "should apply rule if any in array evaluates to true", :third, proc{
      deny :if => [:first?, :second?]
    }

    test_access "should apply rule if all in array evaluates to true", [:first, :second], proc{
      deny :if_all => [:not_first?, :not_second?]
    }

    test_access "should apply rule if any in array evaluates to true", [:first, :second], proc{
      deny :unless => [:first?, :second?]
    }

    test_access "should apply rule if all in array evaluates to true", :third, proc{
      deny :unless_all => [:not_first?, :not_second?]
    }
  end

  describe "with default access" do
    test_access "should allow if allow_by_default", :all, proc{
      allow_by_default
    }

    test_access "should deny if deny_by_default", :none, proc{
      deny_by_default
    }

    test_access "should inherit allow_by_default", :all, proc{
      allow_by_default
    }, proc{
    }

    test_access "should inherit deny_by_default", :none, proc{
      deny_by_default
    }, proc{
    }

    test_access "should rewrite inherited allow_by_default", :none, proc{
      allow_by_default
    }, proc{
      deny_by_default
    }

    test_access "should rewrite inherited deny_by_default", :all, proc{
      deny_by_default
    }, proc{
      allow_by_default
    }
  end
end

describe "passing options" do
  include AccessControllerCreator

  it "should allow valid params" do
    proc{
      create_controller do
        allow :if => :first?, :render => {:nothing => true}, :callback => :notify_admin!
      end
    }.should_not raise_error
  end

  it "should not allow invalid params" do
    proc{
      create_controller do
        allow :none => :first?
      end
    }.should raise_error(ArgumentError)
  end

  it "should not allow multiple condition params" do
    proc{
      create_controller do
        allow :if => :first?, :unless => :second?
      end
    }.should raise_error(ArgumentError)
  end
end
