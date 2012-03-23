require "logstash/filters/base"
require "logstash/namespace"
require "logstash/time"

# The date filter is used for parsing dates from fields and using that
# date or timestamp as the timestamp for the event.
#
# For example, syslog events usually have timestamps like this:
#   "Apr 17 09:32:01"
#
# You would use the date format "MMM dd HH:mm:ss" to parse this.
#
# The date filter is especially important for sorting events and for
# backfilling old data. If you don't get the date correct in your
# event, then searching for them later will likely sort out of order.
#
# In the absence of this filter, logstash will choose a timestamp based on the
# first time it sees the event (at input time), if the timestamp is not already
# set in the event. For example, with file input, the timestamp is set to the
# time of reading.
class LogStash::Filters::Date < LogStash::Filters::Base

  config_name "date"
  plugin_status "stable"

  # Config for date is:
  #   fieldname => dateformat
  #
  # The same field can be specified multiple times (or multiple dateformats for
  # the same field) do try different time formats; first success wins.
  #
  # The date formats allowed are anything allowed by Joda-Time (java time
  # library), generally: [java.text.SimpleDateFormat][dateformats]
  #
  # There are a few special exceptions, the following format literals exist
  # to help you save time and ensure correctness of date parsing.
  #
  # * "ISO8601" - should parse any valid ISO8601 timestamp, such as
  #   2011-04-19T03:44:01.103Z
  # * "UNIX" - will parse unix time in seconds since epoch
  # * "UNIX_MS" - will parse unix time in milliseconds since epoch
  #
  # For example, if you have a field 'logdate' and with a value that looks like 'Aug 13 2010 00:03:44'
  # you would use this configuration:
  #
  #     logdate => "MMM dd yyyy HH:mm:ss"
  #
  # [dateformats]: http://download.oracle.com/javase/1.4.2/docs/api/java/text/SimpleDateFormat.html
  config /[A-Za-z0-9_-]+/, :validate => :array

  # LOGSTASH-34
  DATEPATTERNS = %w{ y d H m s S } 

  # The 'date' filter will take a value from your event and use it as the
  # event timestamp. This is useful for parsing logs generated on remote
  # servers or for importing old logs.
  #
  # The config looks like this:
  #
  # filter {
  #   date {
  #     type => "typename"
  #     fielname => fieldformat
  #
  #     # Example:
  #     timestamp => "mmm DD HH:mm:ss"
  #   }
  # }
  #
  # The format is whatever is supported by Joda; generally:
  # http://download.oracle.com/javase/1.4.2/docs/api/java/text/SimpleDateFormat.html
  #
  # TODO(sissel): Support 'seconds since epoch' parsing (nagios uses this)
  public
  def initialize(config = {})
    super

    @parsers = Hash.new { |h,k| h[k] = [] }
  end # def initialize

  public
  def register
    # TODO(sissel): Need a way of capturing regexp configs better.
    @config.each do |field, value|
      next if RESERVED.include?(field)

      # values here are an array of format strings for the given field.
      missing = []
      value.each do |format|
        case format
        when "ISO8601"
          parser = lambda { |date| DateTime.parse(date) }
        when "UNIX" # unix epoch
          parser = lambda { |date| Time.at(date.to_i).to_datetime }
        when "UNIX_MS" # unix epoch in ms
          parser = lambda { |date| Time.at(date.to_f/1000).to_datetime }
        else
          parser = lambda { |date| DateTime.strptime(date,format) }

          missing = DATEPATTERNS.reject { |p| format.include?(p) }
        end

        @logger.debug("Adding type with date config", :type => @type,
                      :field => field, :format => format)
        @parsers[field] << {
          :parser => parser,
          :missing => missing,
          :format => format
        }
      end # value.each
    end # @config.each
  end # def register

  public
  def filter(event)
    @logger.debug("Date filter: received event", :type => event.type)
    return unless filter?(event)
    now = Time.now

    @parsers.each do |field, fieldparsers|
      @logger.debug("Date filter: type #{event.type}, looking for field #{field.inspect}",
                    :type => event.type, :field => field)
      # TODO(sissel): check event.message, too.
      next unless event.fields.member?(field)

      fieldvalues = event.fields[field]
      fieldvalues = [fieldvalues] if !fieldvalues.is_a?(Array)
      fieldvalues.each do |value|
        next if value.nil?
        begin
          time = nil
          missing = []
          success = false
          last_exception = RuntimeError.new "Unknown"
          fieldparsers.each do |parserconfig|
            parser = parserconfig[:parser]
            missing = parserconfig[:missing]
            #@logger.info :Missing => missing
            #p :parser => parser
            begin
              time = parser.call(value)
              success = true
              break # success
            rescue => e
              @logger.debug("Date parsing failed", :value => value, :format => parserconfig[:format])
              last_exception = e
            end
          end # fieldparsers.each

          if !success
            raise last_exception
          end

          event.timestamp = LogStash::Time.to_iso8601(time.new_offset(0))
          @logger.debug("Date parsing done", :value => value, :timestamp => event.timestamp)
        rescue => e
          @logger.warn("Failed parsing date from field", :field => field,
                       :value => value, :exception => e,
                       :backtrace => e.backtrace)
          # Raising here will bubble all the way up and cause an exit.
          # TODO(sissel): Maybe we shouldn't raise?
          # TODO(sissel): What do we do on a failure? Tag it like grok does?
          #raise e
        end # begin
      end # fieldvalue.each 
    end # @parsers.each

    filter_matched(event) if !event.cancelled?
    return event
  end # def filter
end # class LogStash::Filters::Date
