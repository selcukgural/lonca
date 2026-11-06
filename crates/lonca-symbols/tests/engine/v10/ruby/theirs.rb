require "json"
require_relative "base"

# A client.
class Client < Base
  LIMIT = 10

  def initialize(total)
    @total = total
  end

  def charge(amount)
    @total + amount
  end

  def self.make
    new(1)
  end

  class << self
    def other
      1
    end
  end
end

module Shape
  def area
    1
  end

  def side
    2
  end
end

def top(x)
  x + 1
end

describe "client" do
  it "charges" do
    expect(1).to eq(1)
  end

  xit "refunds" do
    expect(1).to eq(2)
  end
end

class ClientTest < Minitest::Test
  def test_charge
    assert true
  end

  def test_later
    skip
  end
end
