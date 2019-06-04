using NBitcoin;
using System.Reflection;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace NBitcoin.Altcoins
{
	// Reference: https://github.com/btcz/bitcoinz/blob/master/src/chainparams.cpp
	public class Bitcoinz : NetworkSetBase
	{
		public static Bitcoinz Instance { get; } = new Bitcoinz();

		public override string CryptoCode => "BTCZ";

		private Bitcoinz()
		{

		}

		public class BitcoinzConsensusFactory : ConsensusFactory
		{
			private BitcoinzConsensusFactory()
			{
			}

			public static BitcoinzConsensusFactory Instance { get; } = new BitcoinzConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new BitcoinzBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new BitcoinzBlock(new BitcoinzBlockHeader());
			}

			public override Transaction CreateTransaction()
			{
				return new ForkIdTransaction(79, true, this);
			}
		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class BitcoinzBlock : Block
		{
			public BitcoinzBlock(BitcoinzBlockHeader header) : base(header)
			{

			}

			public override ConsensusFactory GetConsensusFactory()
			{
				return BitcoinzConsensusFactory.Instance;
			}
		}
		public class BitcoinzBlockHeader : BlockHeader
		{
			const int SERIALIZE_BLOCK_LEGACY = 0x04000000;

			uint nHeight = 0;

			public uint Height
			{
				get
				{
					return nHeight;
				}
				set
				{
					nHeight = value;
				}
			}

			uint[] vReserved = new uint[7];

			public uint[] Reserved
			{
				get
				{
					return vReserved;
				}
				set
				{
					vReserved = value;
				}
			}

			uint256 nNewNonce = new uint256();

			public uint256 NewNonce
			{
				get
				{
					return nNewNonce;
				}
				set
				{
					nNewNonce = value;
				}
			}

			uint nSolutionSize = 0;

			public uint SolutionSize
			{
				get
				{
					return nSolutionSize;
				}
				set
				{
					nSolutionSize = value;
				}
			}

			byte[] nSolution = new byte[0];

			public byte[] Solution
			{
				get
				{
					return nSolution;
				}
				set
				{
					nSolution = value;
				}
			}

			public override void ReadWrite(BitcoinStream stream)
			{
				var isNewFormat = !stream.Serializing || (nSolutionSize != 0);
				stream.ReadWrite(ref nVersion);
				stream.ReadWrite(ref hashPrevBlock);
				stream.ReadWrite(ref hashMerkleRoot);
				if (isNewFormat)
				{
					stream.ReadWrite(ref nHeight);
					for (int i = 0; i < vReserved.Length; i++)
					{
						uint nReserved = 0;
						stream.ReadWrite(ref nReserved);
						vReserved[i] = nReserved;
					}
				}
				stream.ReadWrite(ref nTime);
				stream.ReadWrite(ref nBits);
				if (isNewFormat)
				{
					stream.ReadWrite(ref nNewNonce);
					stream.ReadWriteAsVarInt(ref nSolutionSize);
					if (nSolutionSize > 0)
					{
						if(!stream.Serializing)
						{
							nSolution = new byte[nSolutionSize];
						}
						stream.ReadWrite(ref nSolution);
					}
				}
				else
				{
					nNonce = nNewNonce.GetLow32();
					stream.ReadWrite(ref nNonce);
					nNewNonce = new uint256(nNonce);
				}
			}
		}
#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("Bitcoinz");
		}


		protected override NetworkBuilder CreateMainnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 840000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 4000,
				BIP34Hash = new uint256S("0x00000000000000000000000000000000000000000000000000a95cc5099213e3"),
				PowLimit = new Target(new uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				MinimumChainWork = new uint256("0000000000000000000000000000000000000000007e5dbf54c7f6b58a6853cd"),
				ConsensusFactory = BitcoinzConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 38 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 23 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("btcz"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("btcz"))
			.SetMagic(0x446d47e1)
			.SetPort(8338)
			.SetRPCPort(8337)
			.SetMaxP2PVersion(70016)
			.SetName("btcz-main")
			.AddAlias("btcz-mainnet")
			.AddAlias("Bitcoinz-mainnet")
			.AddAlias("Bitcoinz-main")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("bitcoingold-official.org", "eu-dnsseed.bitcoingold-official.org"),
				new DNSSeedData("bitcoingold.org", "dnsseed.bitcoingold.org"),
				new DNSSeedData("btcgpu.org", "dnsseed.btcgpu.org"),
			})
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a000000000000000000000000000000000000000000000000000000000000000029ab5f49ffff001d1dac2b7c00000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 2016,
				BIP34Hash = new uint256("0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"),
				PowLimit = new Target(new uint256("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = true,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1512,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				MinimumChainWork = new uint256("00000000000000000000000000000000000000000000002888c34d61b53a244a"),
				ConsensusFactory = BitcoinzConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tbtcz"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tbtcz"))
			.SetMagic(0x456e48e2)
			.SetPort(11988)
			.SetRPCPort(11989)
			.SetMaxP2PVersion(70016)
			.SetName("btcz-test")
			.AddAlias("btcz-testnet")
			.AddAlias("Bitcoinz-test")
			.AddAlias("Bitcoinz-testnet")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("bitcoingold-official.org", "eu-test-dnsseed.bitcoingold-official.org"),
				new DNSSeedData("bitcoingold.org", "test-dnsseed.bitcoingold.org"),
				new DNSSeedData("btcgpu.org", "test-dnsseed.btcgpu.org"),
			})
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a00000000000000000000000000000000000000000000000000000000000000007c355e5affff001d4251bd5600000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 144,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = true,
				MinimumChainWork = uint256.Zero,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 108,
				MinerConfirmationWindow = 144,
				CoinbaseMaturity = 100,
				ConsensusFactory = BitcoinzConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tbtcz"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tbtcz"))
			.SetMagic(0xdab5bffa)
			.SetPort(18444)
			.SetRPCPort(18443)
			.SetMaxP2PVersion(70016)
			.SetName("btcz-reg")
			.AddAlias("btcz-regtest")
			.AddAlias("Bitcoinz-reg")
			.AddAlias("Bitcoinz-regtest")
			.SetGenesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a0000000000000000000000000000000000000000000000000000000000000000dae5494dffff7f200200000000000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
			return builder;
		}
	}
}
