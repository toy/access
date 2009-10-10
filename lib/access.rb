module Access
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def allow(*arguments)
      add_access_rule(:allow, arguments, arguments.extract_options!)
    end

    def deny(*arguments)
      add_access_rule(:deny, arguments, arguments.extract_options!)
    end

    CONDITION_RULE_OPTIONS = [:if, :if_any, :if_all, :unless, :unless_any, :unless_all]
    VALID_RULE_OPTIONS = [:render, :callback] + CONDITION_RULE_OPTIONS

    def allow_by_default
      set_default_access(true)
    end

    def deny_by_default
      set_default_access(false)
    end

    def default_access
      read_inheritable_attribute(:default_access)
    end

    def access_rules
      read_inheritable_attribute(:access_rules)
    end

  private

    def add_access_rule(type, actions, options)
      options.assert_valid_keys(VALID_RULE_OPTIONS)
      condition_option_keys = options.keys & CONDITION_RULE_OPTIONS
      if condition_option_keys.length > 1
        raise(ArgumentError, "There can be only one condition, got #{condition_option_keys.length}: #{condition_option_keys.join(", ")}")
      end

      if read_inheritable_attribute(:access_rules).nil?
        before_filter :access_filter
        write_inheritable_attribute(:access_rules, [])
      end
      write_inheritable_array(:access_rules, [{:allow => type == :allow, :actions => actions, :options => options}])
    end

    def set_default_access(allow)
      if read_inheritable_attribute(:default_access).nil?
        before_filter :default_access_filter
      end
      write_inheritable_attribute(:default_access, allow)
    end
  end

  def access_denied
    redirect_to('/')
  end

private

  def default_access_filter
    if self.class.access_rules.nil? && self.class.default_access == false
      access_denied
    end
  end

  def access_filter
    action = action_name.to_sym

    allow = self.class.default_access

    self.class.access_rules.each do |rule|
      if rule[:allow] != allow && (rule[:actions].empty? || rule[:actions].include?(action))
        pass_block = case
        when cond = rule[:options][:if]
          access_if(cond)
        when cond = rule[:options][:if_all]
          access_if(cond, :all)
        when cond = rule[:options][:if_any]
          access_if(cond, :any)
        when cond = rule[:options][:unless]
          !access_if(cond)
        when cond = rule[:options][:unless_all]
          !access_if(cond, :all)
        when cond = rule[:options][:unless_any]
          !access_if(cond, :any)
        else
          true
        end

        allow = rule[:allow] if pass_block
      end
    end

    access_denied if allow == false
  end

  def access_if(method, conjunction = nil)
    if conjunction
      case method
        when Array
          method.send("#{conjunction}?") do |method|
            access_if(method)
          end
        else
          raise "Unknown type of method #{method.inspect} for #{conjunction}"
      end
    else
      case method
        when Symbol
          send(method)
        when Proc
          instance_eval(&method)
        when String
          instance_eval(method)
        else
          raise "Unknown type of method #{method.inspect}"
      end
    end
  end
end
