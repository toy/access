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

    def add_access_rule(type, actions, options)
      if [:allow, :deny].include?(type)
        if read_inheritable_attribute(:access_rules).nil?
          before_filter :access_filter
          write_inheritable_attribute(:access_rules, [])
        end

        rules = if actions.length > 0
          actions.map do |action|
            {:type => type, :action => action, :options => options}
          end
        else
          [{:type => type, :options => options}]
        end
        write_inheritable_array(:access_rules, rules)
      end
    end

    def access_rules
      read_inheritable_attribute(:access_rules)
    end

    def allow_by_default
      set_default_access(:allow)
    end

    def deny_by_default
      set_default_access(:deny)
    end

    def set_default_access(type)
      if read_inheritable_attribute(:default_access).nil?
        before_filter :default_access_filter
      end
      write_inheritable_attribute(:default_access, type == :allow)
    end

    def default_access
      read_inheritable_attribute(:default_access)
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
    to_render = nil
    callback = nil

    self.class.access_rules.each do |rule|
      if rule[:action].nil? || rule[:action] == action
        to_render = rule[:options][:render] || to_render
        callback = rule[:options][:callback] || callback

        pass_block = if rule[:options][:if]
          access_if(rule[:options][:if])
        elsif rule[:options][:if_all]
          access_if_all(rule[:options][:if_all])
        elsif rule[:options][:if_any]
          access_if_any(rule[:options][:if_any])
        elsif rule[:options][:unless]
          !access_if(rule[:options][:unless])
        elsif rule[:options][:unless_all]
          !access_if_all(rule[:options][:unless_all])
        elsif rule[:options][:unless_any]
          !access_if_any(rule[:options][:unless_any])
        else
          true
        end

        if pass_block
          allow = rule[:type] === :allow ? true : false
        end
      end
    end

    if allow == false
      if to_render
        render to_render.merge(:status => 401)
      elsif callback
        access_run_method(callback)
      else
        access_denied
      end
    end
  end

  def access_if(method)
    case method
      when Symbol
        send(method)
      when Proc, Method
        method.call(self)
      when String
        eval(method)
      when Array
        access_if_all(method)
      else
        raise "Unknown type of method #{method.inspect}"
    end
  end

  def access_if_all(methods)
    methods.all? do |method|
      access_if(method)
    end
  end

  def access_if_any(methods)
    methods.any? do |method|
      access_if(method)
    end
  end
end
