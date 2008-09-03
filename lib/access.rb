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
    render_tmpl = nil
    # callback = nil

    self.class.access_rules.each do |rule|
      if rule[:action].nil? || rule[:action] == action
        render_tmpl ||= rule[:options][:render]
        # callback ||= rule[:options][:callback]

        pass_block = if rule[:options][:if]
          access_filter_condition_result(rule[:options][:if])
        elsif rule[:options][:unless]
          !access_filter_condition_result(rule[:options][:unless])
        else
          true
        end

        if pass_block
          allow = rule[:type] === :allow ? true : false
        end
      end
    end

    if allow == false
      if render_tmpl
        render :action => render_tmpl, :layout => 'error', :status => 401
      # elsif callback
      #   callback.is_a?(Symbol) ? send(callback) : callback.call(self)
      else
        access_denied
      end
    end
  end
  
  def access_filter_condition_result(condition)
    case condition
      when Symbol
        send(condition)
      when Proc
        condition.call(self)
      else
        raise "Unknown type of callback #{condition.inspect}"
    end
  end
end
