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
	use work.keyak_globals.all;

	use work.AEAD_pkg.ALL;

entity CipherCore is
    generic (
        --! Reset behavior
        G_ASYNC_RSTN    : boolean := False; --! Async active low reset
        --! Block size (bits)
        G_DBLK_SIZE     : integer := 544;   --! Data
        G_KEY_SIZE      : integer := 128;   --! Key
        G_TAG_SIZE      : integer := 128;   --! Tag
        --! The number of bits required to hold block size expressed in
        --! bytes = log2_ceil(G_DBLK_SIZE/8)
        G_LBS_BYTES     : integer := 7;
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

component keccakp_round is
port (
    round_in     : in  k_state;
    round_constant_signal    : in std_logic_vector(N-1 downto 0);
    round_out    : out k_state);
end component;

--signals
type fsm_state_type is (s_dummy,s_idle,s_read_key_0,s_read_nonce_0,s_preparing_computing_permutation,s_computing_permutation,s_wait_input,s_generate_and_check_tag,s_wait_tag_read,s_read_exp_tag,s_compelte_buffer_absorb);

signal state,nstate,retstate,reg_retstate: fsm_state_type;
signal secret_and_unique_value: std_logic_vector(suv_size-1 downto 0);

signal round_const: std_logic_vector(N-1 downto 0);
signal round_constant_signal_64: std_logic_vector(63 downto 0);
signal counter_nr_rounds,n_counter_nr_rounds : unsigned(4 downto 0);
signal round_number : unsigned(4 downto 0);
signal reg_data,reg_data_in,round_in,round_out: k_state;
signal key_reg: std_logic_vector(c_G_KEY_SIZE-1 downto 0);
signal nonce_reg: std_logic_vector(c_G_NPUB_SIZE-1 downto 0);
signal sample_key,sample_nonce: std_logic;

signal sample_round_out : std_logic;
signal sample_bdi: std_logic;

signal tag_size_counter,n_tag_size_counter: unsigned(3 downto 0);
signal bdo_write_internal: std_logic;
signal  bdo_reg:  std_logic_vector(G_DBLK_SIZE-1 downto 0);
signal bdo_write_delayed:std_logic;
signal reset_reg_data: std_logic;
signal tag_reg:std_logic_vector(G_TAG_SIZE-1 downto 0);
signal sample_tag:std_logic;
signal bdi_size_delayed: std_logic_vector(G_LBS_BYTES+1    -1  downto 0);
signal verify_tag_flag :std_logic;
signal exp_tag_reg: std_logic_vector(G_TAG_SIZE-1 downto 0);
signal msg_auth_valid_internal,msg_auth_done_internal: std_logic;
signal bdo_size_delayed : std_logic;
signal bdi_eoi_sampled, bdi_eot_sampled: std_logic;
signal bdi_ready_delayed: std_logic;
signal bdi_ready_internal: std_logic;
signal bdi_internal: std_logic_vector(G_DBLK_SIZE             -1 downto 0);

signal is_decrypt   : std_logic;
signal set_no_previous_ad, reset_no_previous_ad, no_previous_ad : std_logic;
signal sample_exp_tag:std_logic;
signal sampled_decrypt:std_logic;
signal tag_output_done, set_tag_output_done,reset_tag_output_done: std_logic;
signal bdi_buffer_in,bdi_buffer : std_logic_vector( G_TAG_SIZE-1 downto 0);
signal buffer_bdi_size : std_logic_vector(G_LBS_BYTES+1    -1 downto 0);
signal sample_bdi_buffer : std_logic;
signal tag_signal : std_logic_vector (127 downto 0);
signal bdi_size_plus_inject_start_offset : std_logic_vector(7 downto 0);
signal empty_message,set_empty_message,reset_empty_message:std_logic;
begin

--port map of components
keccakp_round_0: keccakp_round port map (round_in, round_const, round_out);

	
-- swap bdi for endianess and add pad with zero
p_bdi_internal : process(bdi)
begin
	
	for i in 0 to (G_DBLK_SIZE/8)-1 loop
		if(i < (unsigned(bdi_size))) then		
			-- this endianess shoudl be word boundary and not on block boundary
			bdi_internal(8*(i+1)-1 downto 8*(i))<=bdi(8*((G_DBLK_SIZE/8)-i)-1 downto 8*((G_DBLK_SIZE/8)-1-i)) after k_seq_dly;
		else
			bdi_internal(8*(i+1)-1 downto 8*(i)) <= (others => '0') after k_seq_dly ;
		end if;
	end loop;	
end process;

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
					bdi_ready_delayed <= '0';
					nonce_reg<=(others=>'0');
					tag_reg<=(others=>'0');
					exp_tag_reg<=(others=>'0');
					sampled_decrypt<='0';
					no_previous_ad <='0';
					key_reg<=(others=>'0');
					tag_output_done <= '0';
					for row in 0 to 4 loop
						for col in 0 to 4 loop
							for i in 0 to N-1 loop
								reg_data(row)(col)(i)<='0';
							end loop;
						end loop;
					end loop;		
					bdi_buffer <= (others =>'0');
					reg_retstate <= s_idle;
					empty_message <= '0';
                else
					if(set_empty_message = '1') then
						empty_message <= '1' after k_seq_dly;
					end if;
					if(reset_empty_message = '1' ) then
						empty_message <='0' after k_seq_dly;
					end if;
				
					if(set_no_previous_ad = '1') then
						no_previous_ad <= '1' after k_seq_dly;
					end if;
					if(reset_no_previous_ad = '1' ) then
						no_previous_ad <='0' after k_seq_dly;
					end if;
					reg_retstate <= retstate after k_seq_dly;
					if(sample_bdi_buffer ='1') then	
						bdi_buffer <= bdi_buffer_in after k_seq_dly ;
					end if;				
					if (reset_reg_data='1') then
						for row in 0 to 4 loop
							for col in 0 to 4 loop
								for i in 0 to N-1 loop
									reg_data(row)(col)(i)<='0' after k_seq_dly;
								end loop;
							end loop;
						end loop;
					else
						if(sample_round_out='1') then
							reg_data<=round_out after k_seq_dly;
						else
							reg_data<=reg_data_in after k_seq_dly;
						end if;
					end if;				
					if (sample_key ='1') then
						--key_reg<=key after k_seq_dly;
						for i in 0 to 15 loop
							key_reg(8*(i+1)-1 downto 8*(i))<=key(8*(16-i)-1 downto 8*(15-i)) after k_seq_dly;
						end loop;				
					end if;				
					if (reset_tag_output_done = '1') then
						tag_output_done <= '0' after k_seq_dly;
					end if;
					if (set_tag_output_done = '1') then
						tag_output_done <= '1' after k_seq_dly;
					end if;					
					counter_nr_rounds <= n_counter_nr_rounds after k_seq_dly;
					tag_size_counter <= n_tag_size_counter after k_seq_dly;
				
					if (state = s_wait_input) then
						is_decrypt <= decrypt after k_seq_dly;
					end if;
					state <= nstate after k_seq_dly;
					bdi_ready_delayed <= bdi_ready_internal after k_seq_dly;
					if (sample_nonce ='1') then
						nonce_reg(c_G_NPUB_SIZE-1 downto 0) <=bdi_internal(c_G_NPUB_SIZE-1 downto 0) after k_seq_dly;						
					end if;		
				
		
					if (sample_exp_tag ='1') then
						exp_tag_reg <= bdi_internal(127 downto 0) after k_seq_dly;
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
				bdi_ready_delayed <= '0';
				nonce_reg<=(others=>'0');
				tag_reg<=(others=>'0');
				exp_tag_reg<=(others=>'0');
				sampled_decrypt <= '0';
				no_previous_ad <= '0';
				key_reg<=(others=>'0');
				tag_output_done <= '0';
				for row in 0 to 4 loop
					for col in 0 to 4 loop
						for i in 0 to N-1 loop
							reg_data(row)(col)(i)<='0';
						end loop;
					end loop;
				end loop;		
				bdi_buffer <= (others =>'0');				
				reg_retstate <= s_idle;
				empty_message <='0' ;
            elsif rising_edge(clk) then
				if(set_empty_message = '1') then
					empty_message <= '1' after k_seq_dly;
				end if;
				if(reset_empty_message = '1' ) then
					empty_message <='0' after k_seq_dly;
				end if;			
				reg_retstate <= retstate after k_seq_dly;		
				if(sample_bdi_buffer ='1') then	
					bdi_buffer <= bdi_buffer_in after k_seq_dly ;
				end if;
				if (reset_reg_data='1') then
					for row in 0 to 4 loop
						for col in 0 to 4 loop
							for i in 0 to N-1 loop
								reg_data(row)(col)(i)<='0' after k_seq_dly;
							end loop;
						end loop;
					end loop;
				else
					if(sample_round_out='1') then
						reg_data<=round_out after k_seq_dly;
					else
						reg_data<=reg_data_in after k_seq_dly;
					end if;
				end if;						
				if (sample_key ='1') then
					--key_reg<=key after k_seq_dly;
					for i in 0 to 15 loop
						key_reg(8*(i+1)-1 downto 8*(i))<=key(8*(16-i)-1 downto 8*(15-i)) after k_seq_dly;
					end loop;				
				end if;			
				if (reset_tag_output_done = '1') then
					tag_output_done <= '0' after k_seq_dly;
				end if;
				if (set_tag_output_done = '1') then
					tag_output_done <= '1' after k_seq_dly;
				end if;						
				counter_nr_rounds <= n_counter_nr_rounds after k_seq_dly;
				tag_size_counter <= n_tag_size_counter after k_seq_dly;
			
				if (state = s_wait_input) then
					is_decrypt <= decrypt after k_seq_dly;
				end if;
				state <= nstate after k_seq_dly;
				bdi_ready_delayed <= bdi_ready_internal after k_seq_dly;
				if (sample_nonce ='1') then
					nonce_reg(c_G_NPUB_SIZE-1 downto 0) <=bdi_internal(c_G_NPUB_SIZE-1 downto 0) after k_seq_dly;	
				end if;		
			
	
				if (sample_exp_tag ='1') then
					exp_tag_reg <= bdi_internal(127 downto 0) after k_seq_dly;
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
        bdi_valid, bdi_type, bdi_eot, bdi_eoi, bdi_size,bdi_internal,
        bdo_ready,counter_nr_rounds,tag_size_counter,reg_data,round_in,no_previous_ad,sampled_decrypt,secret_and_unique_value)
  
  begin
		-- default values
	
		--npub_read <= '0' after k_seq_dly;
		--key_updated <='0' after k_seq_dly;
		key_ready <='0' after k_seq_dly;
		--rdkey_read<='0' after k_seq_dly;
		--nsec_read <='0' after k_seq_dly;
		bdi_ready_internal <='0' after k_seq_dly;
		bdo_write_internal<='0' after k_seq_dly;
		
		
		sample_round_out <='0' after k_seq_dly;
		sample_bdi <= '1' after k_seq_dly;
		


		reset_reg_data <='0' after k_seq_dly;
		--tag_write <='0' after k_seq_dly;
		bdi_eoi_sampled <= bdi_eoi after k_seq_dly;
		bdi_eot_sampled <= bdi_eot after k_seq_dly;		
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
		set_no_previous_ad <= '0' after k_seq_dly;
		reset_no_previous_ad <= '0' after k_seq_dly;
		
		nstate <= s_idle after k_seq_dly;
		reg_data_in <= reg_data after k_seq_dly;
		for row in 0 to 4 loop
			for col in 0 to 4 loop
				for i in 0 to N-1 loop
					round_in(row)(col)(i)<='0' after k_seq_dly;
				end loop;
			end loop;
		end loop;		

		bdi_buffer_in <= (others => '0'	) after k_seq_dly;
		sample_bdi_buffer <='0';
		retstate <=  reg_retstate after k_seq_dly;		
		reset_tag_output_done <='0' after k_seq_dly;
		set_tag_output_done <='0' after k_seq_dly;
		reset_empty_message <= '0' after k_seq_dly;
		set_empty_message <= '0' after k_seq_dly;
		
		case state is
		
		
			when s_idle =>

				nstate <= s_idle after k_seq_dly;
                if (bdi_valid = '1') then
                    if (key_update = '1') then
						sample_tag<='0' after k_seq_dly;
						nstate <= s_read_key_0 after k_seq_dly;									
						reset_reg_data <='1' after k_seq_dly;
						reset_tag_output_done <='1' after k_seq_dly;
                    else
						if(bdi_type = BDI_TYPE_NPUB) then
							nstate <=s_read_nonce_0 after k_seq_dly;
							reset_tag_output_done <='1' after k_seq_dly;	
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
					sample_nonce <= '1' after k_seq_dly;
					nstate <= s_preparing_computing_permutation after k_seq_dly;					
					reset_reg_data <='1' after k_seq_dly;
					n_counter_nr_rounds <= "01010" after k_seq_dly;
					if(bdi_eoi ='1' and bdi_eot ='1') then	
						-- no ad and nothing else
						-- btu an additional permutation has to be computed
						-- use empty message signal as flag
						set_empty_message <='1' after k_seq_dly;
					else
						reset_empty_message <= '1' after k_seq_dly;
					end if;
					retstate <= s_wait_input after k_seq_dly;
                end if;

			
			when s_preparing_computing_permutation =>
				nstate <= s_computing_permutation after k_seq_dly;
				
				-- perform permutation
				sample_round_out <='1' after k_seq_dly;				
				n_counter_nr_rounds <= "01011" after k_seq_dly;
				
				-- inject suv
				-- SUV always consists of 24 lane entries. Either 4 of 8 bytes per lane and ((96*8)/32) for river keyak, ((192*8)/64) for others
				-- Inject SUV into state on a lane-by-lane basis

				-- 4 rows of 5 columns
				for row in 0 to 3 loop
					for col in 0 to 4 loop
						for i in 0 to N-1 loop
							round_in(row)(col)(i) <= secret_and_unique_value( ((((row*5)+col)*N)+i) ) after k_seq_dly;
						end loop;
					end loop;
				end loop;

				-- 1 row of 4 columns
				for col in 0 to 3 loop
					for i in 0 to N-1 loop
						round_in(4)(col)(i) <= secret_and_unique_value( ((((4*5)+col)*N)+i) ) after k_seq_dly;
					end loop;
				end loop;

				-- Set InjectEnd offset in state (first byte in last column of last row)
				for i in 0 to 7 loop
					-- set the OEM
					round_in(4)(4)(i + (EOM*8)) <= xff(i) after k_seq_dly;
					round_in(4)(4)(i + (CryptEnd*8)) <=  '0' after k_seq_dly;
					round_in(4)(4)(i + (InjectStart*8)) <= '0' after k_seq_dly;					
					round_in(4)(4)(i + (InjectEnd*8)) <= suv_size_bytes(i) after k_seq_dly;		
				end loop;
				
				reset_tag_output_done <= '1' after k_seq_dly;


			when s_computing_permutation =>
				n_counter_nr_rounds <= counter_nr_rounds + 1 after k_seq_dly;
				sample_round_out <='1' after k_seq_dly;
				round_in <= reg_data;
					
				if(counter_nr_rounds = "10110") then
					nstate <=reg_retstate after k_seq_dly;

							
					sample_round_out <='0' after k_seq_dly;
					n_counter_nr_rounds <= "01010" after k_seq_dly;
					bdi_ready_internal <='0' after k_seq_dly;
					set_no_previous_ad <= '1' after k_seq_dly;
				else 
					nstate <=s_computing_permutation after k_seq_dly;
				end if;
			
			when s_wait_input=>		
				-- process associated data with current state
				nstate <=s_wait_input after k_seq_dly;
				if(empty_message='0') then
					bdi_ready_internal <='1' after k_seq_dly;
				end if;
				
			    if (bdi_valid = '1') then
                    if (bdi_type = BDI_TYPE_ASS0) then
						if(bdi_eot='1')then
							if(bdi_eoi = '0') then
								--next block is message or ciperhtext
								-- no need to compute perutation
								nstate <=s_wait_input after k_seq_dly;
								-- xor in reg_data AD and correpsongin offset 
								-- align to Rs
								for row in 0 to 4 loop
									for col in 0 to 4 loop
										for i in 0 to N-1 loop
											if((row*5+col)>16) then	
												if((row*5*N+col*N+i-(17*N))< (8*(unsigned(bdi_size)))) then								
													reg_data_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_internal(i+(row*5*N+col*N-17*N)) after k_seq_dly;
												else
													reg_data_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
												end if;
											else
												reg_data_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
											end if;
												
										end loop;
									end loop;
								end loop;								
								-- manage offset 
								for i in 0 to 7 loop
									-- set the OEM
									reg_data_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) after k_seq_dly;
									reg_data_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) after k_seq_dly;
									reg_data_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) after k_seq_dly;					
									reg_data_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) xor bdi_size_plus_inject_start_offset(i) after k_seq_dly;		
								end loop;									
-- PATCH bdi size
	--							for i in 0 to 7 loop
	--								reg_data_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) after k_seq_dly;		
	--							end loop;
	--							reg_data_in(4)(4)( (InjectEnd*8)) <= reg_data(4)(4)(0 + (InjectEnd*8)) xor '1' after k_seq_dly;		
	--							reg_data_in(4)(4)( 2+ (InjectEnd*8)) <= reg_data(4)(4)(2 + (InjectEnd*8)) xor '1' after k_seq_dly;		
	--							reg_data_in(4)(4)( 6+ (InjectEnd*8)) <= reg_data(4)(4)(6 + (InjectEnd*8)) xor '1' after k_seq_dly;		
-- END PATCH
							else
								-- AD only
								-- next generate tag
								-- compute permutaiton
								nstate <= s_computing_permutation after k_seq_dly;
								-- perform permutation
								sample_round_out <='1' after k_seq_dly;				
								n_counter_nr_rounds <= "01011" after k_seq_dly;													
								if (sampled_decrypt ='1' ) then
									retstate <= s_read_exp_tag after k_seq_dly;
								else
									retstate <= s_wait_tag_read after k_seq_dly;
								end if;

								-- manage input
								for row in 0 to 4 loop
									for col in 0 to 4 loop
										for i in 0 to N-1 loop
										-- additional condition on i for syntesis
											if(((row*5*N+col*N+i)< (8*(unsigned(bdi_size)))) and ((row*5*N+col*N+i)< G_DBLK_SIZE)) then
												round_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_internal(row*5*N+col*N+i) after k_seq_dly;
											else
												round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
											end if;
										end loop;
									end loop;
								end loop;
								
								-- manage offset
								for i in 0 to 7 loop
									-- set the OEM
									round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) xor eom_tag_size(i) after k_seq_dly;
									round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) after k_seq_dly;
									round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) after k_seq_dly;		
									round_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) xor bdi_size(i) after k_seq_dly;		
								end loop;							
-- HERE PATCH								
--								round_in(4)(4)( (InjectEnd*8)) <= '1' after k_seq_dly;		
--								for i in 1 to 7 loop
--								round_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) after k_seq_dly;		
--								end loop;			
-- end patch								
							end if;		

							reset_no_previous_ad <= '1' after k_seq_dly;
							

						else --bdi_eot='0'
							-- additional AD block to be absorbed
							-- this is not possible, AD max size less than one block
							
						end if;
							

                    elsif (bdi_type = BDI_TYPE_DAT0) then
						if(bdo_ready='1') then
						
							if(sampled_decrypt ='0' and bdi_eot ='0') then
							-- plaintext, more to come
								bdo_valid <= '1' after k_seq_dly;
								bdo <=(others =>'0') after k_seq_dly;
								bdo_size <= bdi_size after k_seq_dly;			
							
							
								-- not last block of message
								bdi_ready_internal <='1' after k_seq_dly;		
								-- go to perform permutation
								
								sample_round_out <='1' after k_seq_dly;
								n_counter_nr_rounds <= "01011" after k_seq_dly;	
								retstate <= s_wait_input after k_seq_dly;
								nstate <=s_computing_permutation after k_seq_dly;

								if(tag_output_done ='1') then
									sample_bdi_buffer <= '1' after k_seq_dly;
									for i in 0 to G_TAG_SIZE loop									
										bdi_buffer_in <= bdi_internal(G_TAG_SIZE-1 downto 0) after k_seq_dly;
									end loop;
								end if;
								
								-- prepare round_in
								if(tag_output_done='0') then								
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop
												if(((row*5*N+col*N+i)< (8*(unsigned(bdi_size)))) and ((row*5*N+col*N+i)< G_DBLK_SIZE)) then
													--add tag flag offset
													round_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_internal(row*5*N+col*N+i) after k_seq_dly;
												else
													round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
												end if;
											end loop;
										end loop;
									end loop;
								else
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop
												if( (row*5*N+col*N+i)< G_TAG_SIZE) then
													round_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_buffer(row*5*N+col*N+i) after k_seq_dly;
												else
													if(((row*5*N+col*N+i)< (8*(unsigned(bdi_size)))) and ((row*5*N+col*N+i)< G_DBLK_SIZE)) then
														round_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_internal(row*5*N+col*N+i-G_TAG_SIZE) after k_seq_dly;
													else
														round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
													end if;
												end if;
											end loop;
										end loop;
									end loop;
									
								end if;									
								
								-- prepare offsets
								if(no_previous_ad ='1') then
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										round_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) xor inject_start_offset(i) after k_seq_dly;		
									end loop;									
								else
									--
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										-- end of AD has been set before via bdi size
									end loop;										
								end if;
								

								-- prepare output
								-- no need to care about bdi size
								for row in 0 to 2 loop
									for col in 0 to 4 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) after k_seq_dly;										
										
										end loop;
									end loop;
								end loop;
								
								for row in 3 to 3 loop
									for col in 0 to 1 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) after k_seq_dly;										
										
										end loop;
									end loop;
								end loop;
	
	
								
						
							elsif(sampled_decrypt ='0' and bdi_eot ='1' ) then
								-- last block of message
								bdo_valid <= '1' after k_seq_dly;
								bdo <=(others =>'0') after k_seq_dly;
								bdo_size <= bdi_size after k_seq_dly;			
							
							
								-- not last block of message
								bdi_ready_internal <='1' after k_seq_dly;		
								-- go to perform permutation
								
								sample_round_out <='1' after k_seq_dly;
								n_counter_nr_rounds <= "01011" after k_seq_dly;	
								
								-- depending on the size of bdi and the data stored on buffer one more permutaiton might be needed								
								if(tag_output_done ='1' and ((8*unsigned(bdi_size)) > (G_DBLK_SIZE-G_TAG_SIZE))) then
									retstate <= s_compelte_buffer_absorb after k_seq_dly;
									sample_bdi_buffer <= '1' after k_seq_dly;
									for i in 0 to G_TAG_SIZE loop									
										bdi_buffer_in <= bdi_internal(G_TAG_SIZE-1 downto 0) after k_seq_dly;
									end loop;
								else
									retstate <= s_wait_tag_read after k_seq_dly;
								end if;
								nstate <=s_computing_permutation after k_seq_dly;
								
								-- prepare round_in
								if(tag_output_done='0') then								
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop
												if((row*5*N+col*N+i)< G_DBLK_SIZE) then
													--add tag flag offset
													round_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_internal(row*5*N+col*N+i) after k_seq_dly;
												else
													round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
												end if;
											end loop;
										end loop;
									end loop;
								else
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop
												if( (row*5*N+col*N+i)< G_TAG_SIZE) then
													round_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_buffer(row*5*N+col*N+i) after k_seq_dly;
												else
													if((row*5*N+col*N+i)< G_DBLK_SIZE) then													
														round_in (row)(col)(i) <= reg_data(row)(col)(i) xor bdi_internal(row*5*N+col*N+i-G_TAG_SIZE) after k_seq_dly;
													else
														round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
													end if;
												end if;
											end loop;
										end loop;
									end loop;
									
								end if;									
								
								
								-- prepare offsets
								if(no_previous_ad ='1') then
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) xor eom_tag_size(i) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										round_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) xor inject_start_offset(i) after k_seq_dly;		
									end loop;									
								else
									--
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) xor eom_tag_size(i) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										-- end of AD has been set before via bdi size
									end loop;										
								end if;
								

								-- prepare output
								-- no need to care about bdi size
								for row in 0 to 2 loop
									for col in 0 to 4 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) after k_seq_dly;										
										
										end loop;
									end loop;
								end loop;
								
								for row in 3 to 3 loop
									for col in 0 to 1 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) after k_seq_dly;										
										
										end loop;
									end loop;
								end loop;							
							elsif(sampled_decrypt ='1' and bdi_eot ='0') then
								-- ciphertext and mro eto come
								-- last block of message
								bdo_valid <= '1' after k_seq_dly;
								bdo <=(others =>'0') after k_seq_dly;
								bdo_size <= bdi_size after k_seq_dly;			
							
							
								-- not last block of message
								bdi_ready_internal <='1' after k_seq_dly;		
								-- go to perform permutation
								
								sample_round_out <='1' after k_seq_dly;
								n_counter_nr_rounds <= "01011" after k_seq_dly;	
								retstate <= s_wait_input after k_seq_dly;
								nstate <=s_computing_permutation after k_seq_dly;

								if(tag_output_done ='1') then
									sample_bdi_buffer <= '1' after k_seq_dly;
									for i in 0 to G_TAG_SIZE loop									
										bdi_buffer_in <= bdi_internal(G_TAG_SIZE-1 downto 0) after k_seq_dly;
									end loop;
								end if;								
								
								-- prepare round_in
								if(tag_output_done='0') then								
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop
												if((row*5*N+col*N+i)< G_DBLK_SIZE) then
													--add tag flag offset
													round_in (row)(col)(i) <= bdi_internal(row*5*N+col*N+i) after k_seq_dly;
												else
													round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
												end if;
											end loop;
										end loop;
									end loop;
								else
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop
												--if( (row*5*N+col*N+i)< (8*unsigned(buffer_bdi_size))) then
												if( (row*5*N+col*N+i)< G_TAG_SIZE) then
													round_in (row)(col)(i) <= bdi_buffer(row*5*N+col*N+i) after k_seq_dly;
												else
													if((row*5*N+col*N+i)< G_DBLK_SIZE) then													
														round_in (row)(col)(i) <= bdi_internal(row*5*N+col*N+i-G_TAG_SIZE) after k_seq_dly;
													else
														round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
													end if;
												end if;
											end loop;
										end loop;
									end loop;
									
								end if;														
								
								-- prepare offsets
								if(no_previous_ad ='1') then
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										round_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) xor inject_start_offset(i) after k_seq_dly;		
									end loop;									
								else
									--
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										-- end of AD has been set before via bdi size
									end loop;										
								end if;				

								-- prepare output
								-- no need to care about bdi size
								for row in 0 to 2 loop
									for col in 0 to 4 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) xor reg_data(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) xor reg_data(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) xor reg_data(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) xor reg_data(row)(col)(i) after k_seq_dly;										
										
										end loop;
									end loop;
								end loop;
								
								for row in 3 to 3 loop
									for col in 0 to 1 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) xor reg_data(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) xor reg_data(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) xor reg_data(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) xor reg_data(row)(col)(i) after k_seq_dly;	
										end loop;
									end loop;
								end loop;
							elsif(sampled_decrypt ='1' and bdi_eot ='1') then
								-- last block of ciphertext 
								
								bdo_valid <= '1' after k_seq_dly;
								bdo <=(others =>'0') after k_seq_dly;
								bdo_size <= bdi_size after k_seq_dly;			
							
							
								-- not last block of message
								bdi_ready_internal <='1' after k_seq_dly;		
								-- go to perform permutation
								
								sample_round_out <='1' after k_seq_dly;
								n_counter_nr_rounds <= "01011" after k_seq_dly;	
								-- depending on the size of bdi and the data soted on buffer one more permutaiton might be needed
								if(tag_output_done ='1' and ((8*unsigned(bdi_size)) > (G_DBLK_SIZE-G_TAG_SIZE))) then
									retstate <= s_compelte_buffer_absorb after k_seq_dly;
									sample_bdi_buffer <= '1' after k_seq_dly;
									for i in 0 to G_TAG_SIZE loop									
										bdi_buffer_in <= bdi_internal(G_TAG_SIZE-1 downto 0) after k_seq_dly;
									end loop;
								else
									retstate <= s_read_exp_tag after k_seq_dly;
								end if;							
								nstate <=s_computing_permutation after k_seq_dly;
								
								-- prepare round_in
								if(tag_output_done='0') then								
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop												
												if(((row*5*N+col*N+i)< (8*(unsigned(bdi_size)))) and ((row*5*N+col*N+i)< G_DBLK_SIZE)) then
													--add tag flag offset
													round_in (row)(col)(i) <= bdi_internal(row*5*N+col*N+i) after k_seq_dly;
												else
													round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
												end if;
											end loop;
										end loop;
									end loop;
								else
									for row in 0 to 4 loop
										for col in 0 to 4 loop
											for i in 0 to N-1 loop
												--if( (row*5*N+col*N+i)< (8* unsigned(buffer_bdi_size))) then
												if( (row*5*N+col*N+i)< G_TAG_SIZE) then
													round_in (row)(col)(i) <= bdi_buffer(row*5*N+col*N+i) after k_seq_dly;
												else
													if(((row*5*N+col*N+i)< (8*(unsigned(bdi_size)))) and ((row*5*N+col*N+i)< G_DBLK_SIZE)) then
														round_in (row)(col)(i) <= bdi_internal(row*5*N+col*N+i-G_TAG_SIZE) after k_seq_dly;
													else
														round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
													end if;
												end if;
											end loop;
										end loop;
									end loop;
									
								end if;		
								
								-- prepare offsets
								if(no_previous_ad ='1') then
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) xor eom_tag_size(i) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										round_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) xor inject_start_offset(i) after k_seq_dly;		
									end loop;									
								else
									--
									for i in 0 to 7 loop
										round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) xor eom_tag_size(i) after k_seq_dly;
										round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) xor bdi_size(i) after k_seq_dly;
										round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) xor inject_start_offset(i) after k_seq_dly;					
										-- end of AD has been set before via bdi size
									end loop;										
								end if;
								


								-- prepare output
								-- no need to care about bdi size
								for row in 0 to 2 loop
									for col in 0 to 4 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) xor reg_data(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) xor reg_data(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) xor reg_data(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) xor reg_data(row)(col)(i) after k_seq_dly;										
										
										end loop;
									end loop;
								end loop;
								
								for row in 3 to 3 loop
									for col in 0 to 1 loop
										for i in 0 to 7 loop
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i) <=round_in(row)(col)(i+24) xor reg_data(row)(col)(i+24) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+8) <=round_in(row)(col)(i+16) xor reg_data(row)(col)(i+16) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+16) <=round_in(row)(col)(i+8) xor reg_data(row)(col)(i+8) after k_seq_dly;
											bdo(G_DBLK_SIZE-(32+col*32+row*32*5) +i+24) <=round_in(row)(col)(i) xor reg_data(row)(col)(i) after k_seq_dly;	
										end loop;
									end loop;
								end loop;

								 
							else

								sample_round_out <='0' after k_seq_dly;			
								nstate <=s_wait_input after k_seq_dly;							
							end if;

						end if;

                    else
                        --! Length type
						
					--if(no_previous_message='1') then
					--	nstate <=s_wait_tag_read after k_seq_dly;
					--else	
					--	nstate <= s_generate_tag_1 after k_seq_dly;
					--end if;
                    end if;
				else
					if(empty_message='1') then
						--perform an additional permutation
						if(sampled_decrypt ='1') then
							retstate <= s_read_exp_tag after k_seq_dly;
						else
							retstate<= s_wait_tag_read after k_seq_dly;
						end if;
						for row in 0 to 4 loop
							for col in 0 to 4 loop
								for i in 0 to N-1 loop
									round_in (row)(col)(i) <= reg_data(row)(col)(i) after k_seq_dly;	
								end loop;
							end loop;
						end loop;
						for i in 0 to 7 loop
								-- set the OEM
								round_in(4)(4)(i + (EOM*8)) <= reg_data(4)(4)(i + (EOM*8)) xor eom_tag_size(i) after k_seq_dly;
								round_in(4)(4)(i + (CryptEnd*8)) <=  reg_data(4)(4)(i + (CryptEnd*8)) after k_seq_dly;
								round_in(4)(4)(i + (InjectStart*8)) <= reg_data(4)(4)(i + (InjectStart*8)) after k_seq_dly;					
								round_in(4)(4)(i + (InjectEnd*8)) <= reg_data(4)(4)(i + (InjectEnd*8)) after k_seq_dly;		
						end loop;	
						sample_round_out <='1' after k_seq_dly;
						n_counter_nr_rounds <= "01011" after k_seq_dly;	
						nstate <=s_computing_permutation after k_seq_dly;						
					else 
						sample_round_out <='0' after k_seq_dly;
						nstate <=s_wait_input after k_seq_dly;					
					end if;

				end if;
			when s_compelte_buffer_absorb =>
				-- to do
				nstate <= s_wait_tag_read after k_seq_dly;	
		
			when s_wait_tag_read =>
				nstate <= s_wait_tag_read after k_seq_dly;	
				if(bdo_ready='1') then
					bdo_valid <='1' after k_seq_dly;						
					bdo_size <= "00010000" after k_seq_dly;			
					-- fix endianess
					for j in 0 to 3 loop
						for i in 0 to 7 loop						
							bdo(G_DBLK_SIZE-(32+j*32) +i) <=reg_data(0)(j)(i+24) after k_seq_dly;
							bdo(G_DBLK_SIZE-(32+j*32) +i+8) <=reg_data(0)(j)(i+16) after k_seq_dly;
							bdo(G_DBLK_SIZE-(32+j*32) +i+16) <=reg_data(0)(j)(i+8) after k_seq_dly;
							bdo(G_DBLK_SIZE-(32+j*32) +i+24) <=reg_data(0)(j)(i) after k_seq_dly;
						end loop;
					end loop;
					nstate <= s_idle after k_seq_dly;
					set_tag_output_done <= '1' after k_seq_dly;

				end if;
			
			when s_read_exp_tag =>
				
				nstate <= s_read_exp_tag after k_seq_dly;		
                if (bdi_valid = '1') then
					bdi_ready_internal <= '1' after k_seq_dly;					
					sample_exp_tag <='1' after k_seq_dly;
					nstate <= s_generate_and_check_tag after k_seq_dly;
				end if;

				
			when s_generate_and_check_tag =>
				msg_auth_done_internal <='1' after k_seq_dly;
				if (tag_signal = exp_tag_reg) then
					msg_auth_valid_internal <='1' after k_seq_dly;
				else
					msg_auth_valid_internal <='0' after k_seq_dly;
				end if;
				nstate <= s_idle after k_seq_dly;
			when others =>
				null;
		end case;
	
  
  end process;
t01: for j in 0 to 3 generate
t02:	for i in 0 to 31 generate
		tag_signal(32*j+i) <=reg_data(0)(j)(i) after k_seq_dly;
	end generate;
end generate;  


	
  
-- Construct SUV = keypack(K, lk)||N = lk||K||padding||N
secret_and_unique_value(7 downto 0) <= key_pack_size_field; -- Set keypack length field
secret_and_unique_value(8+c_G_KEY_SIZE-1 downto 8) <= key_reg; -- Include Key
secret_and_unique_value(16+c_G_KEY_SIZE-1 downto 8+c_G_KEY_SIZE) <= key_pack_padding_start; -- Start padding

-- Pad byte-by-byte till keypack length
do_padding: for i in 0 to (((key_pack_size / 8) - (c_G_KEY_SIZE / 8) - 2)-1) generate
	secret_and_unique_value((8*i)+24+c_G_KEY_SIZE-1 downto (8*i)+16+c_G_KEY_SIZE) <= key_pack_padding;
end generate;

secret_and_unique_value(c_G_NPUB_SIZE+key_pack_size-1 downto key_pack_size) <= nonce_reg; -- Append Nonce
-- pad nonce_reg
secret_and_unique_value(c_G_NPUB_SIZE+key_pack_size+8-1 downto c_G_NPUB_SIZE+key_pack_size) <= "00000001"; 
secret_and_unique_value(suv_size-1 downto c_G_NPUB_SIZE+key_pack_size+8-1) <= (others => '0');



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

bdi_size_plus_inject_start_offset <= std_logic_vector(unsigned(bdi_size)+unsigned(inject_start_offset));

round_const<=round_constant_signal_64(N-1 downto 0);

--output signal
msg_auth_done <= msg_auth_done_internal;
msg_auth_valid <= msg_auth_valid_internal;

bdi_ready <= bdi_ready_internal;

				 


end structure;
