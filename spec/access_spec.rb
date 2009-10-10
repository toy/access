require File.dirname(__FILE__) + '/spec_helper'

module AccessControllerCreator
  def create_controller(&block)
    Class.new(ApplicationController).tap do |controller_class|
      controller_class.class_eval do
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
      controller_class.class_eval(&block) if block
    end
  end

  def test_controller(description, *blocks, &test_block)
    describe '' do
      controller_class = blocks.inject(nil) do |parent, block|
        if parent
          Class.new(parent).tap do |sub_controller_class|
            sub_controller_class.class_eval(&block) if block
          end
        else
          create_controller(&block)
        end
      end
      tests controller_class
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

  describe "with conditions" do
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

    test_access "should apply rule if any in array evaluates to true", :third, proc{
      deny :if_any => [:first?, :second?]
    }

    test_access "should apply rule if all in array evaluates to true", [:first, :second], proc{
      deny :if_all => [:not_first?, :not_second?]
    }

    test_access "should apply rule if any in array evaluates to true", [:first, :second], proc{
      deny :unless_any => [:first?, :second?]
    }

    test_access "should apply rule if all in array evaluates to true", :third, proc{
      deny :unless_all => [:not_first?, :not_second?]
    }

    describe "conditon types" do
      [:if, :unless].each do |condition_name|
        test_controller "should not accept Array for #{condition_name}", proc{
          allow condition_name => []
        } do
          proc{
            get 'first'
          }.should raise_error
        end

        [:first?, proc{ first? }, 'first?'].each do |condition|
          test_controller "should accept #{condition.class} for #{condition_name}", proc{
            allow condition_name => condition
          } do
            proc{
              get 'first'
            }.should_not raise_error
          end
        end
      end

      [:if_any, :if_all, :unless_any, :unless_all].each do |condition_name|
        test_controller "should accept Array for #{condition_name}", proc{
          allow condition_name => []
        } do
          proc{
            get 'first'
          }.should_not raise_error
        end

        [:first?, proc{ first? }, 'first?'].each do |condition|
          test_controller "should not accept #{condition.class} for #{condition_name}", proc{
            allow condition_name => condition
          } do
            proc{
              get 'first'
            }.should raise_error
          end
        end
      end
    end
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

  test_controller "should not run rules that will not change anything", proc{
    allow :if => :a?
    allow :if => :b?
    allow :first, :if => :b?
    deny :if => :c?
    deny :if => :d?
    deny :second, :if => :d?
  } do
    proc{
      controller.should_receive(:a?).and_return(true)
      controller.should_not_receive(:b?)
      controller.should_receive(:c?).and_return(true)
      controller.should_not_receive(:d?)
      get 'first'
    }.should_not raise_error
  end
end

describe "passing wrong options" do
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
