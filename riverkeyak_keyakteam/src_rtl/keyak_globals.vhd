--Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
--Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
--denoted as "the implementer".
--For more information, feedback or questions, please refer to our websites:
--http://keccak.noekeon.org/
--http://keyak.noekeon.org/
--http://ketje.noekeon.org/
--To the extent possible under law, the implementer has waived all copyright
--and related or neighboring rights to the source code in this file.
--http://creativecommons.org/publicdomain/zero/1.0/


library STD;
 use STD.textio.all;


  library IEEE;
    use IEEE.std_logic_1164.all;
    use IEEE.std_logic_misc.all;
    use IEEE.std_logic_arith.all;
    use IEEE.numeric_std.all;

library work;


package keyak_globals is

constant rst_active : std_logic := '1';

-- State constants
constant num_plane : integer := 5; --! Number of Planes
constant num_sheet : integer := 5; --! Number of Sheets

-- River Keyak Constants
constant N : integer := 32; --! Lane Size (bits)
constant squeeze_rate : integer := 68; --! Squeeze Rate Rs (bytes)
constant absorb_rate : integer := 96; --! Absorb Rate Ra (bytes)
constant tau : integer := (128 / 8); --! Tag length in bytes
constant input_max : integer := (squeeze_rate - tau); --! Maximum input length
constant metadata_max : integer := (absorb_rate - squeeze_rate); --! Maximum length of metadata

constant round_nr : std_logic_vector := "1100"; --! Keccak-P Round number
constant capacity : integer := 256; --! Capacity (bits)
constant eom_tag_size : std_logic_vector(7 downto 0) := "00010000"; --! Tag length in bytes: T/8
constant inject_start_offset : std_logic_vector(7 downto 0) := "01000100"; 
constant cprimeprime : std_logic_vector(7 downto 0) := "00100000"; --! Chain length value in bytes: C'/8
constant xff : std_logic_vector(7 downto 0) := X"FF"; --! Piston EOM value when l = 0

constant key_pack_size: integer := 288; --! Key Pack Size (bits)
constant key_pack_size_field : std_logic_vector(7 downto 0) := "00100100"; --! Key Pack Size field (bytes)
constant key_pack_padding_start : std_logic_vector(7 downto 0) := "00000001"; --! Key Pack Padding Start byte
constant key_pack_padding : std_logic_vector(7 downto 0) := "00000000"; --! Key Pack Padding byte
constant diversification_bytes : std_logic_vector(15 downto 0) := "0000000000000001"; --! SUV diversification bytes (0x01 0x00, little endian)
constant suv_size : integer := absorb_rate * 8; --! SUV Size (bits)
--constant suv_size_bytes : std_logic_vector(7 downto 0) := std_logic_vector(to_unsigned(absorb_rate, 8)); --! SUV Size (bytes)
constant suv_size_bytes : std_logic_vector(7 downto 0) := "00110110"; --! SUV Size (bytes)

-- Piston state offsets
constant EOM : integer := 0; --! EOM offset within last column of last row of state
constant CryptEnd : integer := (EOM + 1); --! CryptEnd offset within last column of last row of state
constant InjectStart : integer := (EOM + 2); --! InjectStart offset within last column of last row of state
constant InjectEnd : integer := (EOM + 3); --! InjectEnd offset within last column of last row of state

-- State (sub-)types
type k_row		    is array ((num_sheet-1) downto 0) of std_logic; -- x-axis
type k_column       is array ((num_plane-1) downto 0) of std_logic; -- y-axis
type k_lane         is array ((N-1) downto 0) of std_logic;			-- z-axis

type k_plane        is array ((num_sheet-1) downto 0) of k_lane;	-- x/z plane
type k_slice		is array ((num_sheet-1) downto 0) of k_column;	-- x/y plane
type k_sheet		is array ((num_plane-1) downto 0) of k_lane;	-- z/y plane

type k_state        is array ((num_plane-1) downto 0) of k_plane;  	-- state cube

-- Permutation related (lookup tables, etc.)
type roundcontant_table_type is array (0 to 11) of std_logic_vector(N-1 downto 0);

-- Second half of round constant table (index 10 and up)
constant round_constant_table: roundcontant_table_type := (
		x"80008009", x"8000000A", x"8000808B", x"0000008B",
		x"00008089", x"00008003", x"00008002", x"00000080",
		x"0000800A", x"8000000A", x"80008081", x"00008080");

-- Interface Constants
constant 		k_seq_dly : Time := 1 ns; 
  
constant        c_G_NPUB_SIZE              : integer := 128;  --! Npub size (bits)
constant        c_G_NSEC_SIZE              : integer := 1;     --! Nsec size (bits), NOT USED
constant        c_G_DBLK_SIZE             : integer := 544;     --! Input Data Block size (bits)
constant        c_G_KEY_SIZE               : integer := 128;   --! Key size (bits)
constant        c_G_RDKEY_SIZE             : integer := 1;     --! Round Key size (bits), NOT USED
constant        c_G_TAG_SIZE               : integer := 128;   --! Tag size (bits)
constant        c_G_BS_BYTES               : integer := 8;     --! The number of bits required to hold block size expressed in bytes
constant        c_G_CTR_AD_SIZE            : integer := 64;    --! Maximum size for the counter that keeps track of authenticated data
constant        c_G_CTR_D_SIZE             : integer := 64;    --! Maximum size for the counter that keeps track of data

--constant 		c_G_CSTM_FLAG_SIZE		   : integer := 2;     --! Custom flag vector size
--
--constant 		forget_flag_offset		    : integer := 0;     --! Forget flag offset
--constant 		startengine_tag_flag_offset : integer := 1;     --! Tag flag offset
 





 
end package;