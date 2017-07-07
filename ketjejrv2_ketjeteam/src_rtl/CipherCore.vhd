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

library ieee;
use ieee.std_logic_1164.all;
use IEEE.NUMERIC_STD.all;

library work;
	use work.ketjev2_globals.all;

	use work.AEAD_pkg.ALL;

entity CipherCore is
    generic (
        --! Reset behavior
        G_ASYNC_RSTN    : boolean := False; --! Async active low reset
        --! Block size (bits)
        G_DBLK_SIZE     : integer := 32;   --! Data
        G_KEY_SIZE      : integer := 96;   --! Key
        G_TAG_SIZE      : integer := 64;   --! Tag
        --! The number of bits required to hold block size expressed in
        --! bytes = log2_ceil(G_DBLK_SIZE/8)
        G_LBS_BYTES     : integer := 2;
        --! Maximum supported AD/message/ciphertext length = 2^G_MAX_LEN-1
        G_MAX_LEN       : integer := SINGLE_PASS_MAX		
    );
    port (
        --! Global
        clk             : in  std_logic;
        rst             : in  std_logic;
        --! PreProcessor (data)
        key             : in  std_logic_vector(G_KEY_SIZE       -1 downto 0);
        bdi             : in  std_logic_vector(G_DBLK_SIZE      -1 downto 0);
        --! PreProcessor (controls)
        key_ready       : out std_logic;
        key_valid       : in  std_logic;
        key_update      : in  std_logic;
        decrypt         : in  std_logic;
        bdi_ready       : out std_logic;
        bdi_valid       : in  std_logic;
        bdi_type        : in  std_logic_vector(3                -1 downto 0);
        bdi_partial     : in  std_logic;
        bdi_eot         : in  std_logic;
        bdi_eoi         : in  std_logic;
        bdi_size        : in  std_logic_vector(G_LBS_BYTES+1    -1 downto 0);
        bdi_valid_bytes : in  std_logic_vector(G_DBLK_SIZE/8    -1 downto 0);
        bdi_pad_loc     : in  std_logic_vector(G_DBLK_SIZE/8    -1 downto 0);
        --! PostProcessor
        bdo             : out std_logic_vector(G_DBLK_SIZE      -1 downto 0);
        bdo_valid       : out std_logic;
        bdo_ready       : in  std_logic;
        bdo_size        : out std_logic_vector(G_LBS_BYTES+1    -1 downto 0);
        msg_auth_done   : out std_logic;
        msg_auth_valid  : out std_logic
    );
end entity CipherCore;

architecture structure of CipherCore is

-- components

component ketjev2_round is
port (
    round_in     : in  k_state;
    round_constant_signal    : in std_logic_vector(N-1 downto 0);
    round_out    : out k_state);
end component;

component ketjev2_pi is
port (
    round_in     : in  k_state;
    round_out    : out k_state);
end component;

component ketjev2_inversepi is
port (
    round_in     : in  k_state;    
    round_out    : out k_state);
end component;

--signals
type fsm_state_type is (s_idle,s_read_key_0,s_read_nonce_0,s_read_nonce_1,s_preparing_computing_start,s_computing_start,s_wait_input,s_generate_tag_no_message,s_generate_tag_1,s_generate_tag_2,s_generate_tag_3,s_generate_tag_4,s_generate_and_check_tag,s_wait_tag_read,s_read_exp_tag,s_process_second_half);

signal state,nstate: fsm_state_type;
signal bdi_size_sampled: std_logic_vector(G_LBS_BYTES+1    -1 downto 0);
signal bdi_eoi_sampled,bdi_eot_sampled:std_logic;
signal bdi_type_sampled : std_logic_vector(2 downto 0);
signal round_const: std_logic_vector(N-1 downto 0);
signal round_constant_signal_64: std_logic_vector(63 downto 0);
signal counter_nr_rounds,n_counter_nr_rounds : unsigned(4 downto 0);
signal round_number : unsigned(4 downto 0);
signal reg_data,round_in,round_out,f_round_in,pi_out,invpi_in,invpi_out: k_state;
signal key_reg: std_logic_vector(c_G_KEY_SIZE-1 downto 0);
signal nonce_reg: std_logic_vector(c_G_NPUB_SIZE-1 downto 0);
signal sample_key,sample_nonce,absorb_key_and_nonce,absorb_ad,absorb_decryption: std_logic;
signal key_pack_and_nonce,absorb_data_vector,bdi_vector: std_logic_vector((5*5*N)-1 downto 0);
signal frame_bits: std_logic_vector(3 downto 0);
signal sample_round_out : std_logic;
signal frame_bits_position: std_logic_vector(1 downto 0);
signal tag_size_counter,n_tag_size_counter: unsigned(3 downto 0);
signal reset_reg_data: std_logic;
signal tag_reg:std_logic_vector(G_TAG_SIZE-1 downto 0);
signal sample_tag:std_logic;

signal exp_tag_reg: std_logic_vector(G_TAG_SIZE-1 downto 0);
signal msg_auth_valid_internal,msg_auth_done_internal: std_logic;

signal bdi_ready_internal: std_logic;
signal bdi_internal: std_logic_vector(G_DBLK_SIZE             -1 downto 0);

signal is_decrypt   : std_logic;
signal no_previous_message, reset_no_previous_message, set_no_previous_message : std_logic;
signal sample_exp_tag:std_logic;
signal sampled_decrypt:std_logic;
signal bdi_internal_high,bdi_internal_low,bdi_internal_low_sampled,bdo_reg,n_bdo_reg: std_logic_vector(2*N-1 downto 0);
signal sample_bdis: std_logic;	
signal shift_tag_reg : std_logic;

signal sample_permutation_out,sample_permutationstar_out: std_logic;
signal sample_dout,n_dout_valid, sample_dout_valid,sample_dout_decryption,sample_dout_piout: std_logic;


begin

--port map of components


ketje_round_i: ketjev2_round port map (f_round_in,round_const,round_out );

ketje_pi_i: ketjev2_pi port map (round_out,pi_out );

ketje_invpi_i: ketjev2_inversepi port map (invpi_in,invpi_out );
	
-- swap bdi fo rendianess

bdi_internal<= bdi(7 downto 0) & bdi(15 downto 8) & bdi(23 downto 16) & bdi(31 downto 24);
bdi_internal_low<= bdi(7 downto 0) & bdi(15 downto 8);
bdi_internal_high<= bdi(23 downto 16) & bdi(31 downto 24);

    --! =======================================================================
    --! registers
    --! =======================================================================

	
    gSyncRst:
    if (not G_ASYNC_RSTN) generate
        process(clk)
        begin
            if rising_edge(clk) then
                if (rst = '1') then
                    state <= s_idle;
					is_decrypt <= '0';
					counter_nr_rounds <= (others => '0');
					tag_size_counter  <= (others => '0');
					nonce_reg<=(others=>'0');
					tag_reg<=(others=>'0');
					exp_tag_reg<=(others=>'0');
					sampled_decrypt<='0';
					no_previous_message <='0';
					key_reg<=(others=>'0');
					for row in 0 to 4 loop
						for col in 0 to 4 loop
							for i in 0 to N-1 loop
								reg_data(row)(col)(i)<='0';
							end loop;
						end loop;
					end loop;		
					bdi_internal_low_sampled <= (others=>'0');
					bdi_eoi_sampled <='0';
					bdi_eot_sampled <='0';
					bdi_size_sampled <= "000";
					bdi_type_sampled <= "000";
					bdo_reg <= (others => '0');
                else
					if (sample_bdis ='1') then
						bdi_eoi_sampled <= bdi_eoi after k_seq_dly;
						bdi_eot_sampled <= bdi_eot after k_seq_dly;
						bdi_size_sampled <= bdi_size after k_seq_dly;
						bdi_type_sampled <= bdi_type after k_seq_dly;				
						bdi_internal_low_sampled <= bdi_internal_low after k_seq_dly;
						bdo_reg<= n_bdo_reg after k_seq_dly;
					end if;									
					if(sample_round_out='1') then
						reg_data<=round_out after k_seq_dly;	
					elsif(sample_permutationstar_out='1') then
						reg_data<=pi_out after k_seq_dly;
					end if;
					if (reset_reg_data='1') then
						for row in 0 to 4 loop
							for col in 0 to 4 loop
								for i in 0 to N-1 loop
									reg_data(row)(col)(i)<='0' after k_seq_dly;
								end loop;
							end loop;
						end loop;

					end if;				
					if (sample_key ='1') then
						--key_reg<=key after k_seq_dly;
						for i in 0 to 11 loop
							key_reg(8*(i+1)-1 downto 8*(i))<=key(8*(12-i)-1 downto 8*(11-i)) after k_seq_dly;
						end loop;				
					end if;				
					if (reset_no_previous_message = '1') then
						no_previous_message <= '0' after k_seq_dly;
					end if;
					if (set_no_previous_message = '1') then
						no_previous_message <= '1' after k_seq_dly;
					end if;					
					counter_nr_rounds <= n_counter_nr_rounds after k_seq_dly;
					tag_size_counter <= n_tag_size_counter after k_seq_dly;
				
					if (state = s_wait_input) then
						is_decrypt <= decrypt after k_seq_dly;
					end if;
					state <= nstate after k_seq_dly;
					if (sample_nonce ='1') then
						--nonce_reg<=npub after k_seq_dly;
						
						-- shift words of nonce
						for i in 1 to 1 loop							
							nonce_reg(32*i-1 downto 32*(i-1)) <= nonce_reg(32*(i+1)-1 downto 32*(i)) after k_seq_dly;
						end loop;				
						
						-- inject new words with right endianess
						for i in 0 to 3 loop
							nonce_reg((32+8*(i+1)-1) downto (32+8*(i)))<=bdi(8*(4-i)-1 downto 8*(3-i)) after k_seq_dly;
						end loop;
					end if;		
					if(sample_tag='1') then
						--shift register
						for i in 4 downto 2 loop
							tag_reg(((2*N)*i -1) downto  (2*N)*(i-1))<=tag_reg((2*N)*(i-1) -1 downto  (2*N)*(i-2)) after k_seq_dly;
						end loop;
						for i in 0 to 7 loop				
							tag_reg(i) <=reg_data(0)(1)(i) after k_seq_dly;
							tag_reg(i+N) <=reg_data(0)(0)(i) after k_seq_dly;							
						end loop;
					end if;		
					if(shift_tag_reg='1') then
						--shift register
						tag_reg(63 downto  32)<=tag_reg(31 downto 0) after k_seq_dly;					
					end if;							
					if (sample_exp_tag ='1') then
				
						-- shift words 
						for i in 1 to 1 loop							
							exp_tag_reg(32*(i+1)-1 downto 32*(i)) <= exp_tag_reg(32*i-1 downto 32*(i-1))  after k_seq_dly;
						end loop;										
						-- inject new words with right endianess
						exp_tag_reg(31 downto 0)<=bdi after k_seq_dly;						
					end if;		
					if(state=s_idle) then
						sampled_decrypt <= decrypt after k_seq_dly;
					end if;
					
                end if;
            end if;
        end process;
    end generate;
	
	

	
	
    gAsyncRstn:
    if (G_ASYNC_RSTN) generate
        process(clk, rst)
        begin
            if (rst = '0') then
                state <= s_idle;
				is_decrypt <= '0';
				counter_nr_rounds <= (others => '0');
				tag_size_counter  <= (others => '0');
				nonce_reg<=(others=>'0');
				tag_reg<=(others=>'0');
				exp_tag_reg<=(others=>'0');
				sampled_decrypt <= '0';
				no_previous_message <= '0';
				key_reg<=(others=>'0');
				for row in 0 to 4 loop
					for col in 0 to 4 loop
						for i in 0 to N-1 loop
							reg_data(row)(col)(i)<='0';
						end loop;
					end loop;
				end loop;	
				bdi_internal_low_sampled <= (others=>'0');		
				bdi_eoi_sampled <='0';
				bdi_eot_sampled <='0';
				bdi_size_sampled <= "0000";
				bdi_type_sampled <= "000";		
				bdo_reg<= (others => '0');				
            elsif rising_edge(clk) then
				if (sample_bdis ='1') then
					bdi_eoi_sampled <= bdi_eoi after k_seq_dly;
					bdi_eot_sampled <= bdi_eot after k_seq_dly;
					bdi_size_sampled <= bdi_size after k_seq_dly;
					bdi_type_sampled <= bdi_type after k_seq_dly;				
					bdi_internal_low_sampled <= bdi_internal_low after k_seq_dly;
					bdo_reg<= n_bdo_reg after k_seq_dly;
				end if;				

				if(sample_round_out='1') then
					reg_data<=round_out after k_seq_dly;	
					elsif(sample_permutationstar_out='1') then
						reg_data<=pi_out after k_seq_dly;
					end if;
				if (reset_reg_data='1') then
					for row in 0 to 4 loop
						for col in 0 to 4 loop
							for i in 0 to N-1 loop
								reg_data(row)(col)(i)<='0' after k_seq_dly;
							end loop;
						end loop;
					end loop;

				end if;			
				if (sample_key ='1') then
					--key_reg<=key after k_seq_dly;
					for i in 0 to 11 loop
						key_reg(8*(i+1)-1 downto 8*(i))<=key(8*(12-i)-1 downto 8*(12-i)) after k_seq_dly;
					end loop;					
				end if;			
				if (reset_no_previous_message = '1') then
					no_previous_message <= '0' after k_seq_dly;
				end if;
				if (set_no_previous_message = '1') then
					no_previous_message <= '1' after k_seq_dly;
				end if;					
				counter_nr_rounds <= n_counter_nr_rounds after k_seq_dly;
				tag_size_counter <= n_tag_size_counter after k_seq_dly;
			
				if (state = s_wait_input) then
					is_decrypt <= decrypt after k_seq_dly;
				end if;
				state <= nstate after k_seq_dly;
				if (sample_nonce ='1') then
					--nonce_reg<=npub after k_seq_dly;
					
					-- shift words of nonce
					for i in 1 to 1 loop							
						nonce_reg(32*i-1 downto 32*(i-1)) <= nonce_reg(32*(i+1)-1 downto 32*(i)) after k_seq_dly;
					end loop;				
					
					-- inject new words with right endianess
					for i in 0 to 3 loop
						nonce_reg((32+8*(i+1)-1) downto (32+8*(i)))<=bdi(8*(4-i)-1 downto 8*(3-i)) after k_seq_dly;
					end loop;
				end if;		
				if(sample_tag='1') then
					--shift register
					for i in 4 downto 2 loop
						tag_reg(((2*N)*i -1) downto  (2*N)*(i-1))<=tag_reg((2*N)*(i-1) -1 downto  (2*N)*(i-2)) after k_seq_dly;
					end loop;
					for i in 0 to 7 loop				
						tag_reg(i) <=reg_data(0)(1)(i) after k_seq_dly;
						tag_reg(i+N) <=reg_data(0)(0)(i) after k_seq_dly;	
					end loop;
				end if;		
				if(shift_tag_reg='1') then
					--shift register
					tag_reg(63 downto  32)<=tag_reg(31 downto 0) after k_seq_dly;					
				end if;		
				
				if (sample_exp_tag ='1') then
			
					-- shift words 
					for i in 1 to 1 loop							
						exp_tag_reg(32*(i+1)-1 downto 32*(i)) <= exp_tag_reg(32*i-1 downto 32*(i-1))  after k_seq_dly;
					end loop;										
					-- inject new words with right endianess
					exp_tag_reg(31 downto 0)<=bdi after k_seq_dly;						
				end if;			
				if(state=s_idle) then
					sampled_decrypt <= decrypt after k_seq_dly;
				end if;
				
				
            end if;
        end process;
    end generate;
	
	
	
 -- main process for next state and cotnrol signals
 
  p_main : process( 
        state, key_valid, key_update, is_decrypt, 
        bdi_valid, bdi_type, bdi_eot, bdi_eoi, bdi_size,
        bdo_ready,counter_nr_rounds,tag_size_counter,reg_data,round_in,no_previous_message,sampled_decrypt,invpi_out,round_out,pi_out)	
  
  begin
		-- default values

		key_ready <='0' after k_seq_dly;
		bdi_ready_internal <='0' after k_seq_dly;
		
		
		absorb_key_and_nonce <='0' after k_seq_dly;
		absorb_decryption <='0' after k_seq_dly;
		absorb_ad <= '0' after k_seq_dly;
		sample_round_out <='0' after k_seq_dly;
		
		
		frame_bits_position <= "10" after k_seq_dly;
		frame_bits <="0000" after k_seq_dly;
		reset_reg_data <='0' after k_seq_dly;
		sample_nonce <='0' after k_seq_dly;
		n_counter_nr_rounds <= counter_nr_rounds after k_seq_dly;
		n_tag_size_counter <= (others =>'0') after k_seq_dly;
		sample_key<= '0' after k_seq_dly;
		msg_auth_done_internal <='0' after k_seq_dly;
		msg_auth_valid_internal <='0' after k_seq_dly;
		sample_tag<='0' after k_seq_dly;

		bdo_valid <='0' after k_seq_dly;
		bdo<= (others =>'0') after k_seq_dly;			
		bdo_size <= (others =>'0') after k_seq_dly;			
		sample_exp_tag<= '0'after k_seq_dly;
		set_no_previous_message <= '0' after k_seq_dly;
		reset_no_previous_message <= '0' after k_seq_dly;

		invpi_in <= round_in after k_seq_dly;
		f_round_in <= invpi_out after k_seq_dly;
		sample_dout_piout <= '0' after k_seq_dly;		
		sample_permutationstar_out <='0' after k_seq_dly;
		
		nstate <= s_idle after k_seq_dly;
		sample_bdis <= '0' after k_seq_dly;
		n_bdo_reg <= (others => '0') after k_seq_dly;
		shift_tag_reg<='0' after k_seq_dly;
		case state is
		
		
			when s_idle =>

				nstate <= s_idle after k_seq_dly;
                if (bdi_valid = '1') then
                    if (key_update = '1') then
						sample_tag<='0' after k_seq_dly;
						nstate <= s_read_key_0 after k_seq_dly;									
						reset_reg_data <='1' after k_seq_dly;
                    else
						if(bdi_type = BDI_TYPE_NPUB) then
							nstate <=s_read_nonce_0 after k_seq_dly;
							sample_nonce <='1' after k_seq_dly;
						else
							nstate <=s_wait_input after k_seq_dly;
						end if;

                    end if;
                end if;
				
			when s_read_key_0 =>
				key_ready <='1' after k_seq_dly;
				nstate <=s_read_key_0 after k_seq_dly;
				if(key_valid ='1' ) then			
					sample_key<= '1' after k_seq_dly;
					nstate <=s_idle after k_seq_dly;
				end if;

			when s_read_nonce_0=>
				nstate <=s_read_nonce_0 after k_seq_dly;
				bdi_ready_internal <= '1' after k_seq_dly;
                if (bdi_valid = '1') then
						nstate <=s_read_nonce_1 after k_seq_dly;
						sample_nonce <='1' after k_seq_dly;
                end if;
			
			when s_read_nonce_1=>
				nstate <=s_read_nonce_1 after k_seq_dly;
				bdi_ready_internal <= '1' after k_seq_dly;
                if (bdi_valid = '1') then
						nstate <= s_preparing_computing_start after k_seq_dly;
						sample_nonce <='1' after k_seq_dly;
						n_counter_nr_rounds <= "00110" after k_seq_dly;
						
                end if;
			when s_preparing_computing_start =>
				nstate <= s_computing_start;
				-- perform permutation
				sample_round_out <='1' after k_seq_dly;
				n_counter_nr_rounds <= "00111" after k_seq_dly;
				absorb_key_and_nonce <='1' after k_seq_dly;
						
				-- set frame bits accordingly
				frame_bits <= "0000" after k_seq_dly;

			when s_computing_start =>
				n_counter_nr_rounds <= counter_nr_rounds + 1 after k_seq_dly;
				if(counter_nr_rounds = "10001") then
					sample_permutationstar_out <='1' after k_seq_dly;
				else
					sample_round_out <='1' after k_seq_dly;
				end if;
				
				f_round_in <= round_in after k_seq_dly;
				
					
				if(counter_nr_rounds = "10010") then
					nstate <=s_wait_input after k_seq_dly;

							
					sample_round_out <='0' after k_seq_dly;
					n_counter_nr_rounds <= "10001" after k_seq_dly;
							
					frame_bits <="1100" after k_seq_dly;

					absorb_ad <= '0' after k_seq_dly;
					bdi_ready_internal <='0' after k_seq_dly;
					set_no_previous_message <= '1' after k_seq_dly;
				else 
					nstate <=s_computing_start after k_seq_dly;

					
				end if;
			
			when s_wait_input=>		
				-- process associated data with current state
				nstate <=s_wait_input after k_seq_dly;
				
			    if (bdi_valid = '1') then
                    if (bdi_type = BDI_TYPE_ASS0) then
						
						if(bdi_eot='1')then
							if(bdi_eoi = '0') then
								--last AD but plaintext to come
								if(bdi_size = "100" or bdi_size ="011") then
									nstate <=s_process_second_half after k_seq_dly;
									sample_bdis <= '1' after k_seq_dly;
									n_counter_nr_rounds <= "10001" after k_seq_dly;
								else

									n_counter_nr_rounds <= "10001" after k_seq_dly;
									nstate <=s_wait_input after k_seq_dly;
								end if;
								reset_no_previous_message <= '1' after k_seq_dly;
								bdi_ready_internal <='1' after k_seq_dly;
								-- perform step
								--sample_round_out <='1' after k_seq_dly;
								sample_permutationstar_out <='1' after k_seq_dly;
								-- set frame bits accordingly					
								if(bdi_size = "100" or bdi_size ="011") then
									frame_bits_position <= "10" after k_seq_dly;	
									frame_bits <="1100" after k_seq_dly;
								elsif(bdi_size = "001") then
									frame_bits_position <= "01" after k_seq_dly;	
									frame_bits <="0110" after k_seq_dly;
								elsif(bdi_size = "010") then
									frame_bits_position <= "10" after k_seq_dly;	
									frame_bits <="1110" after k_seq_dly;
								else
									frame_bits_position <= "10" after k_seq_dly;	
									frame_bits <="0110" after k_seq_dly;
								end if;								
								absorb_ad <= '1' after k_seq_dly;								
							else								
								if(bdi_size = "100" or bdi_size ="011") then
									nstate <=s_process_second_half after k_seq_dly;
									sample_bdis <= '1' after k_seq_dly;
									n_counter_nr_rounds <= "10001" after k_seq_dly;
								else
									n_counter_nr_rounds <= "01100" after k_seq_dly;
									nstate <= s_generate_tag_1 after k_seq_dly;
								end if;
								reset_no_previous_message <= '1' after k_seq_dly;
								bdi_ready_internal <='1' after k_seq_dly;
								-- perform step
								--sample_round_out <='1' after k_seq_dly;
								sample_permutationstar_out <='1' after k_seq_dly;
								-- set frame bits accordingly					
								if(bdi_size = "100" or bdi_size ="011") then
									frame_bits_position <= "10" after k_seq_dly;	
									frame_bits <="1100" after k_seq_dly;
								elsif(bdi_size = "001") then
									frame_bits_position <= "01" after k_seq_dly;	
									frame_bits <="0110" after k_seq_dly;
								elsif(bdi_size = "010") then
									frame_bits_position <= "10" after k_seq_dly;	
									frame_bits <="1110" after k_seq_dly;
								else
									frame_bits_position <= "10" after k_seq_dly;	
									frame_bits <="0110" after k_seq_dly;
								end if;
								absorb_ad <= '1' after k_seq_dly;
							end if;		
						else --bdi_eot='0'
							-- additional AD block to be absorbed
							reset_no_previous_message <= '1' after k_seq_dly;
							nstate <=s_process_second_half after k_seq_dly;
							bdi_ready_internal <='1' after k_seq_dly;
							
							--sample_round_out <='1' after k_seq_dly;
							sample_permutationstar_out <='1' after k_seq_dly;

							n_counter_nr_rounds <= "10001" after k_seq_dly;
							
							sample_bdis <= '1' after k_seq_dly;
							frame_bits <="1100" after k_seq_dly;

							absorb_ad <= '1' after k_seq_dly;
						end if;
							

                    elsif (bdi_type = BDI_TYPE_DAT0) then
						if(no_previous_message = '1') then
							reset_no_previous_message <= '1' after k_seq_dly;
							frame_bits_position <= "00" after k_seq_dly;	
							frame_bits <="0110" after k_seq_dly;
							--sample_round_out <='1' after k_seq_dly;
							sample_permutationstar_out <='1' after k_seq_dly;
							n_counter_nr_rounds <= "10001" after k_seq_dly;
							absorb_ad <= '1' after k_seq_dly;					
							nstate <=s_wait_input after k_seq_dly;
						else
							if(bdo_ready='1') then
								if(sampled_decrypt ='0' and bdi_eot ='0') then
									
									bdo <=(others =>'0') after k_seq_dly;
									bdo_size <= bdi_size after k_seq_dly;				
									-- not last block of message
									bdi_ready_internal <='1' after k_seq_dly;		
									-- perform step
									--sample_round_out <='1' after k_seq_dly;
									sample_permutationstar_out <='1' after k_seq_dly;
									n_counter_nr_rounds <= "10001" after k_seq_dly;
									-- set frame bits accordingly				
									frame_bits <="1111" after k_seq_dly;
									absorb_ad <= '1' after k_seq_dly;					
									if(bdi_size="100" or bdi_size = "011") then												
										for i in 0 to 7 loop
											n_bdo_reg(i) <=round_in(0)(1)(i) after k_seq_dly;
											n_bdo_reg(i+N) <=round_in(0)(0)(i) after k_seq_dly;
										end loop;
										sample_bdis <= '1' after k_seq_dly;
										nstate <=s_process_second_half after k_seq_dly;
									elsif(bdi_size="001") then
										nstate <=s_wait_input after k_seq_dly;
										bdo_valid <= '1' after k_seq_dly;
										for i in 0 to 7 loop
											bdo(i+24) <=round_in(0)(0)(i) after k_seq_dly;
										end loop;
									elsif(bdi_size="010") then
										nstate <=s_wait_input after k_seq_dly;
										bdo_valid <= '1' after k_seq_dly;
										for i in 0 to 7 loop
											bdo(i+16) <=round_in(0)(1)(i) after k_seq_dly;
											bdo(i+8+16) <=round_in(0)(0)(i) after k_seq_dly;
										end loop;					
									end if;
						
								elsif(sampled_decrypt ='0' and bdi_eot ='1' ) then
									-- last block of message
									-- need to set counter numebr to right value for the stride
									if(counter_nr_rounds="10001" and (bdi_size="001" or bdi_size = "010")) then
										n_counter_nr_rounds <= "01100" after k_seq_dly;
										nstate <= s_wait_input after k_seq_dly;
										bdo_valid <= '0' after k_seq_dly;
									else										
										bdo <=(others =>'0') after k_seq_dly;
										bdo_size <= bdi_size after k_seq_dly;			
										
										
			
										bdi_ready_internal <='1' after k_seq_dly;		
										
										-- set frame bits accordingly	
										if(bdi_size = "100" or bdi_size = "011") then
											frame_bits_position <= "10" after k_seq_dly;	
											frame_bits <="1111" after k_seq_dly;
											sample_permutationstar_out <='1' after k_seq_dly;
											nstate <= s_process_second_half after k_seq_dly;
											n_counter_nr_rounds <= "01100" after k_seq_dly;
											sample_bdis <='1' after k_seq_dly;
										elsif(bdi_size = "001") then
											frame_bits_position <= "01" after k_seq_dly;	
											frame_bits <="0101" after k_seq_dly;
											sample_round_out <='1' after k_seq_dly;
											nstate <= s_generate_tag_2 after k_seq_dly;
											n_counter_nr_rounds <= "01101" after k_seq_dly;
										elsif(bdi_size = "010") then
											frame_bits_position <= "10" after k_seq_dly;	
											frame_bits <="1101" after k_seq_dly;
											sample_round_out <='1' after k_seq_dly;
											nstate <= s_generate_tag_2 after k_seq_dly;
											n_counter_nr_rounds <= "01101" after k_seq_dly;
										end if;					
									
										absorb_ad <= '1' after k_seq_dly;

										if(bdi_size="100" or bdi_size = "011") then												
											for i in 0 to 7 loop
												n_bdo_reg(i) <=round_in(0)(1)(i) after k_seq_dly;
												n_bdo_reg(i+N) <=round_in(0)(0)(i) after k_seq_dly;
											end loop;
										elsif(bdi_size="001") then
											bdo_valid <= '1' after k_seq_dly;
											for i in 0 to 7 loop
												bdo(i+24) <=round_in(0)(0)(i) after k_seq_dly;
											end loop;											
										elsif(bdi_size="010") then
											bdo_valid <= '1' after k_seq_dly;
											for i in 0 to 7 loop
												bdo(i+16) <=round_in(0)(1)(i) after k_seq_dly;
												bdo(i+N+16) <=round_in(0)(0)(i) after k_seq_dly;
											end loop;					
										end if;
									end if;
									
								
								elsif(sampled_decrypt ='1' and bdi_eot ='0') then
									-- more cipehrtext to come
									bdo <=(others =>'0') after k_seq_dly;
									bdo_size <= bdi_size after k_seq_dly;				
									-- not last block of message
									bdi_ready_internal <='1' after k_seq_dly;		
									-- perform step
									--sample_round_out <='1' after k_seq_dly;
									sample_permutationstar_out <='1' after k_seq_dly;

									n_counter_nr_rounds <= "10001" after k_seq_dly;
									-- set frame bits accordingly				
									frame_bits <="1111" after k_seq_dly;
									absorb_decryption <='1' after k_seq_dly;
									absorb_ad <= '0' after k_seq_dly;

									if(bdi_size="100" or bdi_size = "011") then												
										for i in 0 to 7 loop
											n_bdo_reg(i) <=reg_data(0)(1)(i) xor round_in(0)(1)(i) after k_seq_dly;
											n_bdo_reg(i+N) <=reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
										end loop;
										
										sample_bdis <= '1' after k_seq_dly;
										nstate <=s_process_second_half after k_seq_dly;
									elsif(bdi_size="001") then
										nstate <=s_wait_input after k_seq_dly;
										bdo_valid <= '1' after k_seq_dly;
										for i in 0 to 7 loop
											bdo(i+24) <=reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
										end loop;
									elsif(bdi_size="010") then
										nstate <=s_wait_input after k_seq_dly;
										bdo_valid <= '1' after k_seq_dly;
										for i in 0 to 7 loop
											bdo(i+16) <=reg_data(0)(1)(i) xor round_in(0)(1)(i) after k_seq_dly;
											bdo(i+8+16) <=reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
										end loop;					
									end if;									

								elsif(sampled_decrypt ='1' and bdi_eot ='1') then
									-- last block of message
									-- need to set counter numebr to right value for the stride
									if(counter_nr_rounds="10001" and (bdi_size="001" or bdi_size = "010")) then
										n_counter_nr_rounds <= "01100" after k_seq_dly;
										nstate <= s_wait_input after k_seq_dly;
										bdo_valid <= '0' after k_seq_dly;
									else
										bdo <=(others =>'0') after k_seq_dly;
										bdo_size <= bdi_size after k_seq_dly;			
										
										bdi_ready_internal <='1' after k_seq_dly;	

										-- set frame bits accordingly	
										if(bdi_size = "100" or bdi_size = "011") then
											frame_bits_position <= "10" after k_seq_dly;	
											frame_bits <="1111" after k_seq_dly;
											sample_bdis <= '1' after k_seq_dly;
											sample_permutationstar_out <='1' after k_seq_dly;
											nstate <= s_process_second_half after k_seq_dly;
											n_counter_nr_rounds <= "01100" after k_seq_dly;
											sample_bdis <='1' after k_seq_dly;
										elsif(bdi_size = "001") then
											frame_bits_position <= "01" after k_seq_dly;	
											frame_bits <="0101" after k_seq_dly;
											sample_round_out <='1' after k_seq_dly;					
											nstate <= s_generate_tag_2 after k_seq_dly;
											n_counter_nr_rounds <= "01101" after k_seq_dly;
										elsif(bdi_size = "010") then
											frame_bits_position <= "10" after k_seq_dly;	
											frame_bits <="1101" after k_seq_dly;
											sample_round_out <='1' after k_seq_dly;					
											nstate <= s_generate_tag_2 after k_seq_dly;
											n_counter_nr_rounds <= "01101" after k_seq_dly;
										end if;					
										
										absorb_decryption <='1' after k_seq_dly;
										absorb_ad <= '0' after k_seq_dly;
										
										if(bdi_size="100" or bdi_size = "011") then																							
											for i in 0 to 7 loop
												n_bdo_reg(i) <=reg_data(0)(1)(i) xor round_in(0)(1)(i) after k_seq_dly;
												n_bdo_reg(i+N) <=reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
											end loop;											
										elsif(bdi_size="001") then											
											bdo_valid <= '1' after k_seq_dly;
											for i in 0 to 7 loop
												bdo(i+24) <=reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
											end loop;
										elsif(bdi_size="010") then
											bdo_valid <= '1' after k_seq_dly;
											for i in 0 to 7 loop
												bdo(i+16) <=reg_data(0)(1)(i) xor round_in(0)(1)(i) after k_seq_dly;
												bdo(i+8+16) <=reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
											end loop;					
										end if;									
										
									end if;	
								else
									absorb_ad <= '0' after k_seq_dly;
									sample_round_out <='0' after k_seq_dly;			
									nstate <=s_wait_input after k_seq_dly;							
								end if;
							end if;
						end if;

                    else
                        --! Length type
						
						if(no_previous_message='1') then
							nstate <=s_generate_tag_no_message after k_seq_dly;
							n_counter_nr_rounds <= "10001" after k_seq_dly;
						else	
							nstate <= s_generate_tag_1 after k_seq_dly;
						end if;
                    end if;
				else
					absorb_ad <= '0' after k_seq_dly;
					sample_round_out <='0' after k_seq_dly;
					nstate <=s_wait_input after k_seq_dly;
				end if;
		
			when s_process_second_half=>		
                if (bdi_type_sampled = BDI_TYPE_ASS0) then
					if(bdi_eot_sampled='1')then
						if(bdi_eoi_sampled = '0') then
							n_counter_nr_rounds <= "10001" after k_seq_dly;
							nstate <=s_wait_input after k_seq_dly;
						else
							n_counter_nr_rounds <= "01100" after k_seq_dly;
							nstate <= s_generate_tag_1 after k_seq_dly;
						end if;		

						reset_no_previous_message <= '1' after k_seq_dly;
						bdi_ready_internal <='0' after k_seq_dly;
						-- perform step
						--sample_round_out <='1' after k_seq_dly;
						sample_permutationstar_out <='1' after k_seq_dly;

						
						-- set frame bits accordingly					
						if(bdi_size_sampled = "100") then
							frame_bits_position <= "10" after k_seq_dly;	
							frame_bits <="1110" after k_seq_dly;
						elsif(bdi_size_sampled = "011") then
							frame_bits_position <= "01" after k_seq_dly;	
							frame_bits <="0110" after k_seq_dly;
						else
							-- shoudl never happen
							frame_bits_position <= "00" after k_seq_dly;	
							frame_bits <="0110" after k_seq_dly;
						end if;
						
						absorb_ad <= '1' after k_seq_dly;
					else --bdi_eot='0'
						-- additional AD block to be absorbed
						reset_no_previous_message <= '1' after k_seq_dly;
						nstate <=s_wait_input after k_seq_dly;
						bdi_ready_internal <='0' after k_seq_dly;
				
						--sample_round_out <='1' after k_seq_dly;
						sample_permutationstar_out <='1' after k_seq_dly;

						n_counter_nr_rounds <= "10001" after k_seq_dly;
						
						frame_bits_position <= "10" after k_seq_dly;	
						frame_bits <="1100" after k_seq_dly;

						absorb_ad <= '1' after k_seq_dly;
					end if;
						

				elsif (bdi_type_sampled = BDI_TYPE_DAT0) then
					if(no_previous_message = '1') then
						reset_no_previous_message <= '1' after k_seq_dly;
						frame_bits_position <= "00" after k_seq_dly;	
						frame_bits <="0110" after k_seq_dly;
						sample_round_out <='1' after k_seq_dly;
						n_counter_nr_rounds <= "10001" after k_seq_dly;
						absorb_ad <= '1' after k_seq_dly;					
						nstate <=s_wait_input after k_seq_dly;
					else
						if(bdo_ready='1') then
							if(sampled_decrypt ='0' and bdi_eot_sampled ='0') then
								bdo_valid <= '1' after k_seq_dly;
								bdo <=(others =>'0') after k_seq_dly;
								bdo_size <= bdi_size_sampled after k_seq_dly;			
							
							
								-- not last block of message
								bdi_ready_internal <='0' after k_seq_dly;		
								-- perform step
								--sample_round_out <='1' after k_seq_dly;
								sample_permutationstar_out <='1' after k_seq_dly;

								n_counter_nr_rounds <= "10001" after k_seq_dly;
								-- set frame bits accordingly				
								frame_bits <="1111" after k_seq_dly;
								absorb_ad <= '1' after k_seq_dly;					

								if(bdi_size_sampled="100") then										
									for i in 0 to N-1 loop
										bdo(i+3*N) <=bdo_reg(i+N) after k_seq_dly;
										bdo(i+2*N) <=bdo_reg(i) after k_seq_dly;
										bdo(i+N) <=round_in(0)(0)(i) after k_seq_dly;
										bdo(i) <=round_in(0)(1)(i) after k_seq_dly;
									end loop;
								elsif(bdi_size_sampled="011") then
									for i in 0 to 7 loop
										bdo(i+3*N) <=bdo_reg(i+N) after k_seq_dly;
										bdo(i+2*N) <=bdo_reg(i) after k_seq_dly;
										bdo(i+N) <=round_in(0)(0)(i) after k_seq_dly;
									end loop;					
								end if;																	
								nstate <=s_wait_input after k_seq_dly;
					
							elsif(sampled_decrypt ='0' and bdi_eot_sampled ='1' ) then
								-- last block of message
								-- need to set counter numebr to right value for the stride
								if(counter_nr_rounds="10011") then
									n_counter_nr_rounds <= "01110" after k_seq_dly;
									nstate <= s_wait_input after k_seq_dly;
									bdo_valid <= '0' after k_seq_dly;
								else
									bdo_valid <= '1' after k_seq_dly;
									bdo <=(others =>'0') after k_seq_dly;
									bdo_size <= bdi_size_sampled after k_seq_dly;			
								
									n_counter_nr_rounds <= "01101" after k_seq_dly;
									sample_round_out <='1' after k_seq_dly;					
									bdi_ready_internal <='0' after k_seq_dly;		

									-- no need of a further step
									-- set frame bits accordingly	
									if(bdi_size_sampled = "100") then
										frame_bits_position <= "10" after k_seq_dly;	
										frame_bits <="1101" after k_seq_dly;
									elsif(bdi_size_sampled = "011") then
										frame_bits_position <= "01" after k_seq_dly;	
										frame_bits <="0101" after k_seq_dly;
									else
										-- shoudl never happen
										frame_bits_position <= "01" after k_seq_dly;	
										frame_bits <="0101" after k_seq_dly;
									end if;					
								
									absorb_ad <= '1' after k_seq_dly;
									
									nstate <= s_generate_tag_2 after k_seq_dly;
									if(bdi_size_sampled="100") then										
										for i in 0 to N-1 loop
											bdo(i+3*N) <=bdo_reg(i+N) after k_seq_dly;
											bdo(i+2*N) <=bdo_reg(i) after k_seq_dly;
											bdo(i+N) <=round_in(0)(0)(i) after k_seq_dly;
											bdo(i) <=round_in(0)(1)(i) after k_seq_dly;
										end loop;
									elsif(bdi_size_sampled="011") then
										for i in 0 to 7 loop
											bdo(i+3*N) <=bdo_reg(i+N) after k_seq_dly;
											bdo(i+2*N) <=bdo_reg(i) after k_seq_dly;
											bdo(i+N) <=round_in(0)(0)(i) after k_seq_dly;
										end loop;					
									end if;									
								end if;
								
							
							elsif(sampled_decrypt ='1' and bdi_eot_sampled ='0') then
								bdi_ready_internal <='0' after k_seq_dly;		
								-- perform step
								--sample_round_out <='1' after k_seq_dly;
								sample_permutationstar_out <='1' after k_seq_dly;

								n_counter_nr_rounds <= "10001" after k_seq_dly;
								-- set frame bits accordingly				
								frame_bits <="1111" after k_seq_dly;
								absorb_decryption <='1' after k_seq_dly;
								absorb_ad <= '0' after k_seq_dly;
								bdo_valid <= '1' after k_seq_dly;						
								if(bdi_size_sampled="100") then										
									for i in 0 to N-1 loop
										bdo(i+3*N) <= bdo_reg(i+N) after k_seq_dly;
										bdo(i+2*N) <= bdo_reg(i) after k_seq_dly;
										bdo(i+N) <= reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
										bdo(i) <= reg_data(0)(1)(i) xor round_in(0)(1)(i) after k_seq_dly;		
									end loop;
								elsif(bdi_size_sampled="011") then
									for i in 0 to 7 loop
										bdo(i+3*N) <= bdo_reg(i+N) after k_seq_dly;
										bdo(i+2*N) <= bdo_reg(i) after k_seq_dly;
										bdo(i+N) <= reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
									end loop;					
								end if;
							
								nstate <=s_wait_input after k_seq_dly;
							elsif(sampled_decrypt ='1' and bdi_eot_sampled ='1') then
								-- last block of message
								-- need to set counter numebr to right value for the stride
								if(counter_nr_rounds="10011") then
									n_counter_nr_rounds <= "01110" after k_seq_dly;
									nstate <= s_wait_input after k_seq_dly;
									bdo_valid <= '0' after k_seq_dly;
								else
									bdo_valid <= '1' after k_seq_dly;
									bdo <=(others =>'0') after k_seq_dly;
									bdo_size <= bdi_size_sampled after k_seq_dly;			
										
									-- perform stride
									n_counter_nr_rounds <= "01101" after k_seq_dly;
									sample_round_out <='1' after k_seq_dly;					
									bdi_ready_internal <='0' after k_seq_dly;	

									-- set frame bits accordingly
									if(bdi_size_sampled = "100") then
										frame_bits_position <= "10" after k_seq_dly;	
										frame_bits <="1101" after k_seq_dly;
									elsif(bdi_size_sampled = "011") then
										frame_bits_position <= "01" after k_seq_dly;	
										frame_bits <="0101" after k_seq_dly;
									else
										-- shoudl never happen
										frame_bits_position <= "01" after k_seq_dly;	
										frame_bits <="0101" after k_seq_dly;
									end if;	
									
									absorb_decryption <='1' after k_seq_dly;
									absorb_ad <= '0' after k_seq_dly;
									
									if(bdi_size_sampled="100") then										
										for i in 0 to N-1 loop
											bdo(i+3*N) <= bdo_reg(i+N) after k_seq_dly;
											bdo(i+2*N) <= bdo_reg(i) after k_seq_dly;
											bdo(i+N) <= reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
											bdo(i) <= reg_data(0)(1)(i) xor round_in(0)(1)(i) after k_seq_dly;		
										end loop;
									elsif(bdi_size_sampled="011") then
										for i in 0 to 7 loop
											bdo(i+3*N) <= bdo_reg(i+N) after k_seq_dly;
											bdo(i+2*N) <= bdo_reg(i) after k_seq_dly;
											bdo(i+N) <= reg_data(0)(0)(i) xor round_in(0)(0)(i) after k_seq_dly;
										end loop;					
									end if;									
									
									nstate <= s_generate_tag_2 after k_seq_dly;
								end if;	
							else
								absorb_ad <= '0' after k_seq_dly;
								sample_round_out <='0' after k_seq_dly;			
								nstate <=s_wait_input after k_seq_dly;							
							end if;
						end if;
					end if;

				else
					--! Length type
					
					if(no_previous_message='1') then
						nstate <=s_generate_tag_no_message after k_seq_dly;
					else	
						nstate <= s_generate_tag_1 after k_seq_dly;
					end if;
				end if;

			
			when s_generate_tag_no_message =>
				
				absorb_ad <= '1' after k_seq_dly;
				frame_bits_position <= "00" after k_seq_dly;
				frame_bits <= "0110" after k_seq_dly;
				--sample_round_out <='1' after k_seq_dly;
				sample_permutationstar_out <='1' after k_seq_dly;				
				n_counter_nr_rounds <= "01100" after k_seq_dly;
				nstate <= s_generate_tag_1 after k_seq_dly;
			when s_generate_tag_1 =>	
				absorb_ad <= '1' after k_seq_dly;		
				frame_bits_position <= "00" after k_seq_dly;
				frame_bits <= "0101" after k_seq_dly;
				sample_round_out <='1' after k_seq_dly;					
				n_counter_nr_rounds <= "01101" after k_seq_dly;
				nstate <= s_generate_tag_2 after k_seq_dly;
			when s_generate_tag_2 =>
				absorb_decryption <='0' after k_seq_dly;				
				absorb_ad <= '0' after k_seq_dly;		
				f_round_in <= round_in after k_seq_dly;
				n_counter_nr_rounds <= counter_nr_rounds + 1 after k_seq_dly;
				-- almost odne, one more round
				if(counter_nr_rounds = "10001") then
					nstate <= s_generate_tag_3 after k_seq_dly;
					n_counter_nr_rounds <= "10001" after k_seq_dly;
					sample_permutationstar_out <='1' after k_seq_dly;
				else
					nstate <= s_generate_tag_2 after k_seq_dly;
					sample_round_out <='1' after k_seq_dly;
				end if;
			when s_generate_tag_3 =>
					absorb_ad <= '1' after k_seq_dly;	
					--sample_round_out <='1' after k_seq_dly;
					sample_permutationstar_out <='1' after k_seq_dly;
	
					frame_bits_position <= "00" after k_seq_dly;
					-- perform step					
					frame_bits <="0010" after k_seq_dly;
					n_counter_nr_rounds <= "10001" after k_seq_dly;
					nstate <= s_generate_tag_4 after k_seq_dly;				
					sample_tag<='1' after k_seq_dly;
					n_tag_size_counter<= "0001" after k_seq_dly;
					
			
			when s_generate_tag_4 =>
				frame_bits <="0010" after k_seq_dly;
				absorb_ad <= '1' after k_seq_dly;	
				frame_bits_position <= "00" after k_seq_dly;
				n_tag_size_counter <= tag_size_counter + 1 after k_seq_dly;
				sample_tag<='1' after k_seq_dly;
				--sample_round_out <='1' after k_seq_dly;
				sample_permutationstar_out <='1' after k_seq_dly;
				nstate <= s_generate_tag_4 after k_seq_dly;		
				if(tag_size_counter="0011") then
					sample_round_out <='0' after k_seq_dly;
				end if;
				if(tag_size_counter="0100") then
					sample_tag<='0' after k_seq_dly;		
					sample_round_out <='0' after k_seq_dly;
					absorb_ad <= '0' after k_seq_dly;
					n_tag_size_counter <="0000" after k_seq_dly;
					
					
					if (sampled_decrypt ='1') then
						nstate <= s_read_exp_tag after k_seq_dly;
					else
						nstate <= s_wait_tag_read after k_seq_dly;						
					end if;

				end if;
			when s_wait_tag_read =>
				nstate <= s_wait_tag_read after k_seq_dly;	
				n_tag_size_counter <= tag_size_counter after k_seq_dly;
				if(bdo_ready='1') then
					shift_tag_reg<='1' after k_seq_dly;
					n_tag_size_counter <= tag_size_counter + 1 after k_seq_dly;
					bdo_valid <='1' after k_seq_dly;
					bdo_size <= "100" after k_seq_dly;			
					bdo<= tag_reg(63 downto 32) after k_seq_dly;
					if(tag_size_counter="0001") then
						n_tag_size_counter <="0000" after k_seq_dly;
						nstate <= s_idle after k_seq_dly;
					end if;				
				end if;
			
			when s_read_exp_tag =>
				
				nstate <= s_read_exp_tag after k_seq_dly;		
                if (bdi_valid = '1') then
					bdi_ready_internal <= '1' after k_seq_dly;					
					sample_exp_tag <='1' after k_seq_dly;
					n_tag_size_counter <= tag_size_counter + 1 after k_seq_dly;
			
					if(tag_size_counter="0001") then
						nstate <= s_generate_and_check_tag after k_seq_dly;
						n_tag_size_counter <="0000" after k_seq_dly;	
					end if;
				end if;

				
			when s_generate_and_check_tag =>
				msg_auth_done_internal <='1' after k_seq_dly;
				if (tag_reg = exp_tag_reg) then
					msg_auth_valid_internal <='1' after k_seq_dly;
				else
					msg_auth_valid_internal <='0' after k_seq_dly;
				end if;
				nstate <= s_idle after k_seq_dly;
			when others =>
				null;
		end case;
	
  
  end process;
  
key_pack_and_nonce(7 downto 0)<=key_pack_size;

key_pack_and_nonce (8+c_G_KEY_SIZE-1 downto 8)<= key_reg;
key_pack_and_nonce (16+c_G_KEY_SIZE-1 downto 8+c_G_KEY_SIZE)<=key_pack_padding ;
key_pack_and_nonce (16+c_G_NPUB_SIZE+c_G_KEY_SIZE-1 downto 16+c_G_KEY_SIZE)<=nonce_reg ;
key_pack_and_nonce (24+c_G_NPUB_SIZE+c_G_KEY_SIZE-1 downto 16+c_G_NPUB_SIZE+c_G_KEY_SIZE)<=start_padding;
key_pack_and_nonce (191 downto 24+c_G_NPUB_SIZE+c_G_KEY_SIZE)<=(others=>'0');
key_pack_and_nonce (199 downto 192) <= end_padding;


absorb_data_vector(N-1 downto 0) <= bdi_internal_high(N-1 downto 0) when ((frame_bits_position="10" or frame_bits_position="01") and (state = s_wait_input)) else
								bdi_internal_low_sampled(N-1 downto 0) when ((frame_bits_position="10" or frame_bits_position="01") and (state = s_process_second_half)) else
							("0000" & frame_bits);

absorb_data_vector(2*N-1 downto N) <= bdi_internal_high(2*N-1 downto N) when (frame_bits_position="10" and (state = s_wait_input)) else
								bdi_internal_low_sampled(2*N-1 downto N) when (frame_bits_position="10" and (state = s_process_second_half)) else
								("0000" & frame_bits) when frame_bits_position="01" else
								(others=> '0');

								
absorb_data_vector(2*N+3 downto 2*N) <= frame_bits when (frame_bits_position="10") else 
								"1000" ;



								
absorb_data_vector(5*5*N-1 downto N*2+4) <= (others=> '0');





bdi_vector(N-1 downto 0) <= bdi_internal_high(N-1 downto 0) when  ((frame_bits_position="10" or frame_bits_position="01") and (state = s_wait_input)) else
							bdi_internal_low_sampled(N-1 downto 0) when  ((frame_bits_position="10" or frame_bits_position="01") and (state = s_process_second_half)) else
							("0000" & frame_bits);

bdi_vector((N*2)-1 downto N) <= bdi_internal_high((N*2)-1 downto N) when (frame_bits_position="10"  and (state = s_wait_input)) else
								bdi_internal_low_sampled((N*2)-1 downto N) when (frame_bits_position="10" and (state = s_process_second_half)) else
								("0000" & frame_bits) xor(reg_data(0)(1)(7) & reg_data(0)(1)(6) &reg_data(0)(1)(5) &reg_data(0)(1)(4) &reg_data(0)(1)(3) &reg_data(0)(1)(2) &reg_data(0)(1)(1) &reg_data(0)(1)(0) ) when frame_bits_position="01" else
								(others=> '0');

								
bdi_vector(N*2+3 downto N*2) <= frame_bits when (frame_bits_position="10") else 
								"1000" ;
								
bdi_vector(5*5*N-1 downto N*2+4) <= (others=> '0');


--col 0 byte 0
		i012: for i in 0 to 7 generate
			round_in(0)(0)(i)<= key_pack_and_nonce(0*5*N+ 0*N+i) when (absorb_key_and_nonce='1') else
									(absorb_data_vector(0*5*N+ 0*N+i) xor reg_data(0)(0)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*n+ 0*N+i) when (absorb_decryption='1') else
									reg_data(0)(0)(i);
		end generate;
		
-- col 1 byte 0
		i012b: for i in 0 to 7 generate
			round_in(0)(1)(i)<= key_pack_and_nonce(0*5*N+ 1*N+i) when (absorb_key_and_nonce='1') else
									(absorb_data_vector(0*5*N+ 1*N+i) xor reg_data(0)(1)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*n+ 1*N+i) when (absorb_decryption='1') else
									reg_data(0)(1)(i);
		end generate;


	i0011: for col in 2 to 4 generate
		i0012: for i in 0 to N-1 generate
			round_in(0)(col)(i)<= key_pack_and_nonce(0*5*N+ col*N+i) when (absorb_key_and_nonce='1') else
									(absorb_data_vector(0*5*N+ col*N+i) xor reg_data(0)(col)(i)) when (absorb_ad='1') else
									(bdi_vector(0*5*n+ col*N+i) xor reg_data(0)(col)(i)) when (absorb_decryption='1') else
									reg_data(0)(col)(i);
		end generate;	
	end generate;

i10: for row in 1 to 4 generate
	i11: for col in 0 to 4 generate
		i12: for i in 0 to N-1 generate
			round_in(row)(col)(i)<= key_pack_and_nonce(row*5*N+ col*N+i) when (absorb_key_and_nonce='1') else
									(absorb_data_vector(row*5*N+ col*N+i) xor reg_data(row)(col)(i)) when (absorb_ad='1') else
									reg_data(row)(col)(i) when (absorb_decryption='1') else
									reg_data(row)(col)(i);
		end generate;	
	end generate;
end generate;


round_constants : process (counter_nr_rounds)
begin
	case counter_nr_rounds is
        when "00000" => round_constant_signal_64 <= X"0000000000000001" ;
	    when "00001" => round_constant_signal_64 <= X"0000000000008082" ;
	    when "00010" => round_constant_signal_64 <= X"800000000000808A" ;
	    when "00011" => round_constant_signal_64 <= X"8000000080008000" ;
	    when "00100" => round_constant_signal_64 <= X"000000000000808B" ;
	    when "00101" => round_constant_signal_64 <= X"0000000080000001" ;
	    when "00110" => round_constant_signal_64 <= X"8000000080008081" ;
	    when "00111" => round_constant_signal_64 <= X"8000000000008009" ;
	    when "01000" => round_constant_signal_64 <= X"000000000000008A" ;
	    when "01001" => round_constant_signal_64 <= X"0000000000000088" ;
	    when "01010" => round_constant_signal_64 <= X"0000000080008009" ;
	    when "01011" => round_constant_signal_64 <= X"000000008000000A" ;
	    when "01100" => round_constant_signal_64 <= X"000000008000808B" ;
	    when "01101" => round_constant_signal_64 <= X"800000000000008B" ;
	    when "01110" => round_constant_signal_64 <= X"8000000000008089" ;
	    when "01111" => round_constant_signal_64 <= X"8000000000008003" ;
	    when "10000" => round_constant_signal_64 <= X"8000000000008002" ;
	    when "10001" => round_constant_signal_64 <= X"8000000000000080" ;
	    when "10010" => round_constant_signal_64 <= X"000000000000800A" ;
	    when "10011" => round_constant_signal_64 <= X"800000008000000A" ;
	    when "10100" => round_constant_signal_64 <= X"8000000080008081" ;
	    when "10101" => round_constant_signal_64 <= X"8000000000008080" ;
	    when "10110" => round_constant_signal_64 <= X"0000000080000001" ;
	    when "10111" => round_constant_signal_64 <= X"8000000080008008" ;	    	    
	    when others => round_constant_signal_64 <=(others => '0');
        end case;
end process round_constants;

round_const<=round_constant_signal_64(N-1 downto 0);

--output signal
msg_auth_done <= msg_auth_done_internal;
msg_auth_valid <= msg_auth_valid_internal;


bdi_ready <= bdi_ready_internal;

end structure;
