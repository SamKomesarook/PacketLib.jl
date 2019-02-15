@testset "EthAddr Raw" begin
   @test etheraddr_raw(0x45) == [69, 0, 0, 0, 0, 0]
   @test etheraddr_raw([0x45]) == [69, 0, 0, 0, 0, 0]
   @test etheraddr_raw("ff:ff:ff:ff:ff:ff") == [255, 255, 255, 255, 255, 255]
   @test etheraddr_raw(45) == [45, 0, 0, 0, 0, 0]
   @test etheraddr_raw([45]) == [45, 0, 0, 0, 0, 0]
   @test etheraddr_raw(b"\xff\xff@") == [255, 255, 64, 0, 0, 0]
end

@testset "EthType Raw" begin
   @test ethertype_raw(0x90) == [144,0]
   @test ethertype_raw([0x90]) == [144, 0]
   @test ethertype_raw("9000") == [144,0]
   @test ethertype_raw(9000) == [144,0]
   @test ethertype_raw([90]) == [90,0]
   @test ethertype_raw(b"\x90\x00") == [144,0]
   @test ethertype_raw(0x9000) == [144,0]
   @test ethertype_raw("ipv4") == [8,0]
end

@testset "EthPayload Raw" begin
   @test etherpayload_raw(0x90) == [144]
   @test etherpayload_raw([0x90]) == [144]
   @test etherpayload_raw("9000") == [57, 48, 48, 48]
   @test etherpayload_raw(90) == [90]
   @test etherpayload_raw([90]) == [90]
   @test etherpayload_raw(b"\xff\xff@") == [255,255,64]
end
