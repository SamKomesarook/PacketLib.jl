using Test

tests = ["ethertests"]
for t in tests
  include("$(t).jl")
end
