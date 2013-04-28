package com.tomek.rd.saimek;

import javacardx.crypto.Cipher;

public interface SaimekConstants {

	/**
	 * Debug errors, to be removed from the release
	 */
	static final byte[] ERROR1 = { (byte) 'E', (byte) 'r', (byte) 'r',
			(byte) 'o', (byte) 'r', (byte) '1' };
	static final byte[] ERROR2 = { (byte) 'E', (byte) 'r', (byte) 'r',
			(byte) 'o', (byte) 'r', (byte) '2' };
	static final byte[] ERROR3 = { (byte) 'E', (byte) 'r', (byte) 'r',
			(byte) 'o', (byte) 'r', (byte) '3' };
	static final byte[] ERROR4 = { (byte) 'E', (byte) 'r', (byte) 'r',
		(byte) 'o', (byte) 'r', (byte) '4' };
	static final byte[] ERROR5 = { (byte) 'E', (byte) 'r', (byte) 'r', (byte) 'o',
		(byte) 'r', (byte) '5' };
	static final byte[] ERROR_NOT_SUPPORTED = { (byte) 'A', (byte) 'l', (byte) 'g',
		(byte) '.', (byte) ' ',	(byte) 'N', (byte) 'o', (byte) 't', (byte) 'S',
		(byte) 'u', (byte) 'p', (byte) 'p', (byte) 'o', (byte) 'r', (byte) 't', (byte) 'e', 
		(byte) 'd' };
	
	public static final byte CRYPTO_ALGORITHM_TYPE = Cipher.ALG_DES_CBC_NOPAD;

	/**
	 * This is the back selection value defined by ICM
	 */
	public static final byte BACK_SELECTION = (byte) 0xFF;

	/**
	 * This is the back selection value defined by ICM
	 */
	public static final byte TERMINATE_SESSION_SELECTION = (byte) 0xFE;

	/**
	 * This is the yesResponse constant value sent by the MOBILE
	 */
	public static final byte[] YES_RESPONSE = { (byte) 0x01 };
	
	public static final byte TRUE = (byte) 1;
	public static final byte FALSE = (byte) 0;

	/**
	 * Authentication response success
	 */
	public static final byte TAG_AUTH_RESPONSE = (byte) 0x01;

	/**
	 * Error unspecified
	 */
	public static final byte TAG_ERROR_UNSPECIFIED = (byte) 0x80;
	
	/**
	 * buffer used to store source number of SMS message 
	 */
	public static final byte[] SMS_DESTINATION_NUMBER =  { (byte) 0x91, (byte) 0x44,
		(byte) 0x77, (byte) 0x79, (byte) 0x88, (byte) 0x72, (byte) 0x99 };
	
	/**
	 * actions types received in a text message from the IP-SIM gateway
	 */
	// Store credentials 
	public static final byte ACTION_STORE_CREDENTIALS = 0x31;
	// Retrieve credentails 
	public static final byte ACTION_RETRIEVE_CREDENTIALS = 0x32;
	// Send logins to the IP-SIM proxy server
	public static final byte ACTION_SEND_LOGINS_BACKUP = 0x33;
	// Request logins from IP-SIM proxy server
	public static final byte ACTION_REQUEST_LOGINS_BACKUP = 0x34;
	
	/**
	 * Length converter value. It is required to convert real value
	 * encoded in binary format to a format that can be sent to the 
	 * IP-SIM gateway using http GET method. It will not be required
	 * if we use SMPP protocol to interconnect IP-SIM GW with SMSC
	 */
	public static final byte LENGTH_CONVERTER_VALUE = 0x40;
	
	/**
	 * Default PIN code value
	 */
	static final byte[] DEFAULT_PIN_CODE_NUMBER = { (byte) 0x31, (byte) 0x32,
			(byte) 0x33, (byte) 0x34 };

	/*
	 * the authentication key is hardcoded (for debug). It is suggested to later
	 * set it as installation parameter to avoid having to recompile the applet
	 * for each SIM it will be load into and maximise security
	 */
	byte[] SERVER_KEY_ARRAY = { (byte) 0, (byte) 0, (byte) 0, (byte) 0,
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
			(byte) 0, (byte) 0 };

	/**
	 * @SMS_TPDU_TLV_1_part is the first part of the SMS-submit TPDU
	 * 
	 * @SMS_TPDU (TP-MTI,TP-RD,TP-VPF,TP-SRR,TP-UDHI,TP-RP) : 0x11h
	 * @TP_MR : 0xFFh
	 * @note_1 : TP-RD is set to 0b, so the SMSC will have to accept the
	 *         SMS-submit with the same TP-MR and TP-DA
	 * @note_2 : operator has to confirm that they do not need to synchronise
	 *         the SMS message reference with the EF SMSS file and their SMSC.
	 */
	public static final byte[] SMS_TPDU_TLV_1_part = { (byte) 0x11, (byte) 0xFF };

	/**
	 * SMS_TPDU_TLV_3_part_8bit represents the third part of the TPDU buffer
	 * (the second part is appended by the sendSMS method)
	 * 
	 * @TP-PID : 0x00h
	 * @TP_DCS : 0x04h (i.e. default 8 bits alphabets unpacked format, class
	 *         less)
	 * @TP_VP : 143d = 12h
	 */
	public static final byte[] SMS_TPDU_TLV_3_part_8bit = { (byte) 0x00,
			(byte) 0x04, (byte) 143 };

	/**
	 * This is an empty buffer used to set the ALPHA_IDENTIFIER to null
	 */
	public static final byte[] EMPTY = {};
	
	/**
	 * Encoding method
	 * 
	 * @Example according to the tab below : if the text is "Call me later", the
	 *          maximum length is 30(+3), the length is 14, and the identifier
	 *          1, then the coding is {(byte) 33, (byte) 14, (byte) 1, (byte)
	 *          67, (byte) 97, (byte) 108, (byte) 108, (byte) 32, (byte) 109,
	 *          (byte) 101, (byte) 32, (byte) 108, (byte) 97, (byte) 116, (byte)
	 *          101, (byte) 114} and so on.
	 *          
	 */

	public static final byte[] menuVariables = {(byte)23,(byte)21,(byte)1, (byte) '0', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)2, (byte) '1', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)3, (byte) '2', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)4, (byte) '3', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)5, (byte) '4', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)6, (byte) '5', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)7, (byte) '6', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)8, (byte) '7', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)9, (byte) '8', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)23,(byte)21,(byte)10, (byte) '9', (byte) 'm', (byte) 'y', (byte) 'o', (byte) 'r', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',(byte)43,(byte)41,(byte)11, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0',(byte)19,(byte)17,(byte)12, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0',(byte)43,(byte)41,(byte)13, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1',(byte)19,(byte)17,(byte)14, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1', (byte) '1',(byte)43,(byte)41,(byte)15, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2',(byte)19,(byte)17,(byte)16, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2', (byte) '2',(byte)43,(byte)41,(byte)17, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3',(byte)19,(byte)17,(byte)18, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3', (byte) '3',(byte)43,(byte)41,(byte)19, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4',(byte)19,(byte)17,(byte)20, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4', (byte) '4',(byte)43,(byte)41,(byte)21, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5',(byte)19,(byte)17,(byte)22, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5', (byte) '5',(byte)43,(byte)41,(byte)23, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6',(byte)19,(byte)17,(byte)24, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6', (byte) '6',(byte)43,(byte)41,(byte)25, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7',(byte)19,(byte)17,(byte)26, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7', (byte) '7',(byte)43,(byte)41,(byte)27, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8',(byte)19,(byte)17,(byte)28, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8', (byte) '8',(byte)43,(byte)41,(byte)29, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9',(byte)19,(byte)17,(byte)30, (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9', (byte) '9',(byte)23,(byte)12,(byte)31, (byte) 'S', (byte) 'e', (byte) 'n', (byte) 'd', (byte) ' ', (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) 's',(byte)23,(byte)15,(byte)32, (byte) 'R', (byte) 'e', (byte) 'c', (byte) 'e', (byte) 'i', (byte) 'v', (byte) 'e', (byte) ' ', (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) 's',(byte)13,(byte)5,(byte)33, (byte) 'E', (byte) 'x', (byte) 'i', (byte) 't',(byte)23,(byte)7,(byte)34, (byte) 'S', (byte) 'a', (byte) 'i', (byte) 'm', (byte) 'e', (byte) 'k',(byte)23,(byte)11,(byte)35, (byte) 'E', (byte) 'd', (byte) 'i', (byte) 't', (byte) ' ', (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n',(byte)23,(byte)14,(byte)36, (byte) 'E', (byte) 'd', (byte) 'i', (byte) 't', (byte) ' ', (byte) 'P', (byte) 'a', (byte) 's', (byte) 's', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'd',(byte)23,(byte)18,(byte)37, (byte) 'E', (byte) 'd', (byte) 'i', (byte) 't', (byte) ' ', (byte) 'A', (byte) 'c', (byte) 'c', (byte) 'o', (byte) 'u', (byte) 'n', (byte) 't', (byte) ' ', (byte) 'N', (byte) 'a', (byte) 'm', (byte) 'e',(byte)23,(byte)18,(byte)38, (byte) 'C', (byte) 'h', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) ' ', (byte) 'P', (byte) 'I', (byte) 'N', (byte) ' ', (byte) 'n', (byte) 'u', (byte) 'm', (byte) 'b', (byte) 'e', (byte) 'r',(byte)33,(byte)24,(byte)39, (byte) 'T', (byte) 'y', (byte) 'p', (byte) 'e', (byte) ' ', (byte) 'i', (byte) 'n', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) 'r', (byte) ' ', (byte) 'P', (byte) 'I', (byte) 'N', (byte) ' ', (byte) 'n', (byte) 'u', (byte) 'm', (byte) 'b', (byte) 'e', (byte) 'r',(byte)33,(byte)28,(byte)40, (byte) 'T', (byte) 'y', (byte) 'p', (byte) 'e', (byte) ' ', (byte) 'i', (byte) 'n', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) 'r', (byte) ' ', (byte) 'o', (byte) 'l', (byte) 'd', (byte) ' ', (byte) 'P', (byte) 'I', (byte) 'N', (byte) ' ', (byte) 'n', (byte) 'u', (byte) 'm', (byte) 'b', (byte) 'e', (byte) 'r',(byte)33,(byte)22,(byte)41, (byte) 'T', (byte) 'y', (byte) 'p', (byte) 'e', (byte) ' ', (byte) 'a', (byte) ' ', (byte) 'n', (byte) 'e', (byte) 'w', (byte) ' ', (byte) 'P', (byte) 'I', (byte) 'N', (byte) ' ', (byte) 'n', (byte) 'u', (byte) 'm', (byte) 'b', (byte) 'e', (byte) 'r',(byte)33,(byte)28,(byte)42, (byte) 'T', (byte) 'y', (byte) 'p', (byte) 'e', (byte) ' ', (byte) 'a', (byte) ' ', (byte) 'n', (byte) 'e', (byte) 'w', (byte) ' ', (byte) 'P', (byte) 'I', (byte) 'N', (byte) ' ', (byte) 'n', (byte) 'u', (byte) 'm', (byte) 'b', (byte) 'e', (byte) 'r', (byte) ' ', (byte) 'a', (byte) 'g', (byte) 'a', (byte) 'i', (byte) 'n',(byte)33,(byte)24,(byte)43, (byte) 'P', (byte) 'I', (byte) 'N', (byte) ' ', (byte) 'n', (byte) 'u', (byte) 'm', (byte) 'b', (byte) 'e', (byte) 'r', (byte) ' ', (byte) 'i', (byte) 's', (byte) ' ', (byte) 'n', (byte) 'o', (byte) 't', (byte) ' ', (byte) 'v', (byte) 'a', (byte) 'l', (byte) 'i', (byte) 'd',(byte)43,(byte)29,(byte)44, (byte) 'D', (byte) 'o', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) ' ', (byte) 'w', (byte) 'a', (byte) 'n', (byte) 't', (byte) ' ', (byte) 't', (byte) 'o', (byte) ' ', (byte) 's', (byte) 'a', (byte) 'v', (byte) 'e', (byte) ' ', (byte) 'c', (byte) 'h', (byte) 'a', (byte) 'n', (byte) 'g', (byte) 'e', (byte) 's', (byte) '?',(byte)43,(byte)39,(byte)45, (byte) 'D', (byte) 'o', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) ' ', (byte) 'w', (byte) 'a', (byte) 'n', (byte) 't', (byte) ' ', (byte) 't', (byte) 'o', (byte) ' ', (byte) 's', (byte) 'e', (byte) 'n', (byte) 'd', (byte) ' ', (byte) 'l', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) 's', (byte) ' ', (byte) 't', (byte) 'o', (byte) ' ', (byte) 't', (byte) 'h', (byte) 'e', (byte) ' ', (byte) 's', (byte) 'r', (byte) 'v', (byte) '?',(byte)43,(byte)37,(byte)46, (byte) 'D', (byte) 'o', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) ' ', (byte) 'w', (byte) 'a', (byte) 'n', (byte) 't', (byte) ' ', (byte) 't', (byte) 'o', (byte) ' ', (byte) 'r', (byte) 'e', (byte) 'c', (byte) 'e', (byte) 'i', (byte) 'v', (byte) 'e', (byte) ' ', (byte) 's', (byte) 'a', (byte) 'v', (byte) 'e', (byte) 'd', (byte) ' ', (byte) 'l', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) 's', (byte) '?',(byte)43,(byte)12,(byte)47, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) 's', (byte) ' ', (byte) 's', (byte) 'e', (byte) 'n', (byte) 't',(byte)43,(byte)16,(byte)48, (byte) 'L', (byte) 'o', (byte) 'g', (byte) 'i', (byte) 'n', (byte) 's', (byte) ' ', (byte) 'r', (byte) 'e', (byte) 'c', (byte) 'e', (byte) 'i', (byte) 'v', (byte) 'e', (byte) 'd',(byte)13,(byte)7,(byte)49, (byte) 'E', (byte) 'r', (byte) 'r', (byte) 'o', (byte) 'r', (byte) '!',(byte)23,(byte)13,(byte)50, (byte) 'O', (byte) 'p', (byte) 'e', (byte) 'n', (byte) ' ', (byte) 'b', (byte) 'r', (byte) 'o', (byte) 'w', (byte) 's', (byte) 'e', (byte) 'r',(byte)43,(byte)22,(byte)51, (byte) 'V', (byte) 'i', (byte) 'e', (byte) 'w', (byte) '/', (byte) 'E', (byte) 'd', (byte) 'i', (byte) 't', (byte) ' ', (byte) 'C', (byte) 'r', (byte) 'e', (byte) 'd', (byte) 'e', (byte) 'n', (byte) 't', (byte) 'i', (byte) 'a', (byte) 'l', (byte) 's',(byte)43,(byte)19,(byte)52, (byte) 'N', (byte) 'e', (byte) 'w', (byte) ' ', (byte) 'v', (byte) 'a', (byte) 'l', (byte) 'u', (byte) 'e', (byte) ' ', (byte) 'a', (byte) 'c', (byte) 'c', (byte) 'e', (byte) 'p', (byte) 't', (byte) 'e', (byte) 'd',(byte)23,(byte)18,(byte)53, (byte) 'E', (byte) 'd', (byte) 'i', (byte) 't', (byte) ' ', (byte) 'A', (byte) 'c', (byte) 'c', (byte) 'o', (byte) 'u', (byte) 'n', (byte) 't', (byte) ' ', (byte) 'N', (byte) 'a', (byte) 'm', (byte) 'e',(byte)23,(byte)21,(byte)54, (byte) 'B', (byte) 'r', (byte) 'o', (byte) 'w', (byte) 's', (byte) 'e', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) 'r', (byte) ' ', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e', (byte) 's',(byte)23,(byte)20,(byte)55, (byte) 'S', (byte) 'e', (byte) 'l', (byte) 'e', (byte) 'c', (byte) 't', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) 'r', (byte) ' ', (byte) 'w', (byte) 'e', (byte) 'b', (byte) 's', (byte) 'i', (byte) 't', (byte) 'e',(byte)23,(byte)14,(byte)56, (byte) 'A', (byte) 'u', (byte) 't', (byte) 'o', (byte) 'm', (byte) 'a', (byte) 't', (byte) 'i', (byte) 'c', (byte) ' ', (byte) 'P', (byte) 'I', (byte) 'N',(byte)43,(byte)40,(byte)57, (byte) 'D', (byte) 'o', (byte) ' ', (byte) 'y', (byte) 'o', (byte) 'u', (byte) ' ', (byte) 'w', (byte) 'a', (byte) 'n', (byte) 't', (byte) ' ', (byte) 't', (byte) 'o', (byte) ' ', (byte) 's', (byte) 'w', (byte) 'i', (byte) 't', (byte) 'c', (byte) 'h', (byte) ' ', (byte) '1', (byte) 'h', (byte) ' ', (byte) 'a', (byte) 'u', (byte) 't', (byte) 'o', (byte) 'm', (byte) 'a', (byte) 't', (byte) 'i', (byte) 'c', (byte) ' ', (byte) 'P', (byte) 'I', (byte) 'N', (byte) '?'};

	public static final byte VAR_1= (byte) 1; //0myorangewebsite.com (20)
	public static final byte VAR_2= (byte) 2; //1myorangewebsite.com (20)
	public static final byte VAR_3= (byte) 3; //2myorangewebsite.com (20)
	public static final byte VAR_4= (byte) 4; //3myorangewebsite.com (20)
	public static final byte VAR_5= (byte) 5; //4myorangewebsite.com (20)
	public static final byte VAR_6= (byte) 6; //5myorangewebsite.com (20)
	public static final byte VAR_7= (byte) 7; //6myorangewebsite.com (20)
	public static final byte VAR_8= (byte) 8; //7myorangewebsite.com (20)
	public static final byte VAR_9= (byte) 9; //8myorangewebsite.com (20)
	public static final byte VAR_10= (byte) 10; //9myorangewebsite.com (20)
	public static final byte VAR_11= (byte) 11; //Login00000000000000000000000000000000000 (40)
	public static final byte VAR_12= (byte) 12; //Password00000000 (16)
	public static final byte VAR_13= (byte) 13; //Login11111111111111111111111111111111111 (40)
	public static final byte VAR_14= (byte) 14; //Password11111111 (16)
	public static final byte VAR_15= (byte) 15; //Login22222222222222222222222222222222222 (40)
	public static final byte VAR_16= (byte) 16; //Password22222222 (16)
	public static final byte VAR_17= (byte) 17; //Login33333333333333333333333333333333333 (40)
	public static final byte VAR_18= (byte) 18; //Password33333333 (16)
	public static final byte VAR_19= (byte) 19; //Login44444444444444444444444444444444444 (40)
	public static final byte VAR_20= (byte) 20; //Password44444444 (16)
	public static final byte VAR_21= (byte) 21; //Login55555555555555555555555555555555555 (40)
	public static final byte VAR_22= (byte) 22; //Password55555555 (16)
	public static final byte VAR_23= (byte) 23; //Login66666666666666666666666666666666666 (40)
	public static final byte VAR_24= (byte) 24; //Password66666666 (16)
	public static final byte VAR_25= (byte) 25; //Login77777777777777777777777777777777777 (40)
	public static final byte VAR_26= (byte) 26; //Password77777777 (16)
	public static final byte VAR_27= (byte) 27; //Login88888888888888888888888888888888888 (40)
	public static final byte VAR_28= (byte) 28; //Password88888888 (16)
	public static final byte VAR_29= (byte) 29; //Login99999999999999999999999999999999999 (40)
	public static final byte VAR_30= (byte) 30; //Password99999999 (16)
	public static final byte VAR_31= (byte) 31; //Send Logins (20)
	public static final byte VAR_32= (byte) 32; //Receive Logins (20)
	public static final byte VAR_33= (byte) 33; //Exit (10)
	public static final byte VAR_34= (byte) 34; //Saimek (20)
	public static final byte VAR_35= (byte) 35; //Edit Login (20)
	public static final byte VAR_36= (byte) 36; //Edit Password (20)
	public static final byte VAR_37= (byte) 37; //Edit Account Name (20)
	public static final byte VAR_38= (byte) 38; //Change PIN number (20)
	public static final byte VAR_39= (byte) 39; //Type in your PIN number (30)
	public static final byte VAR_40= (byte) 40; //Type in your old PIN number (30)
	public static final byte VAR_41= (byte) 41; //Type a new PIN number (30)
	public static final byte VAR_42= (byte) 42; //Type a new PIN number again (30)
	public static final byte VAR_43= (byte) 43; //PIN number is not valid (30)
	public static final byte VAR_44= (byte) 44; //Do you want to save changes? (40)
	public static final byte VAR_45= (byte) 45; //Do you want to send logins to the srv? (40)
	public static final byte VAR_46= (byte) 46; //Do you want to receive saved logins? (40)
	public static final byte VAR_47= (byte) 47; //Logins sent (40)
	public static final byte VAR_48= (byte) 48; //Logins received (40)
	public static final byte VAR_49= (byte) 49; //Error! (10)
	public static final byte VAR_50= (byte) 50; //Open browser (20)
	public static final byte VAR_51= (byte) 51; //View/Edit Credentials (40)
	public static final byte VAR_52= (byte) 52; //New value accepted (40)
	public static final byte VAR_53= (byte) 53; //Edit Account Name (20)
	public static final byte VAR_54= (byte) 54; //Browse your websites (20)
	public static final byte VAR_55= (byte) 55; //Select your website (20)
	public static final byte VAR_56= (byte) 56; //Automatic PIN (20)
	public static final byte VAR_57= (byte) 57; //Do you want to switch 1h automatic PIN? (40)

	public static final short[] MENU_VARIABLES_POINTER_SUMMARY = {(short)0,(short)0,(short)23,(short)46,(short)69,(short)92,(short)115,(short)138,(short)161,(short)184,(short)207,(short)230,(short)273,(short)292,(short)335,(short)354,(short)397,(short)416,(short)459,(short)478,(short)521,(short)540,(short)583,(short)602,(short)645,(short)664,(short)707,(short)726,(short)769,(short)788,(short)831,(short)850,(short)864,(short)881,(short)888,(short)897,(short)910,(short)926,(short)946,(short)966,(short)992,(short)1022,(short)1046,(short)1076,(short)1102,(short)1133,(short)1174,(short)1213,(short)1227,(short)1245,(short)1254,(short)1269,(short)1293,(short)1314,(short)1334,(short)1357,(short)1379,(short)1395};

	public static final byte[] MAIN_MENU_POINTER_SUMMARY = { (byte) VAR_54,
			(byte) VAR_37, (byte) VAR_38, (byte) VAR_31, (byte) VAR_32,
			(byte) VAR_56, (byte) VAR_33};

	public static final byte[] ACCOUNT_NAMES_POINTER_SUMMARY = { (byte) VAR_1,
			(byte) VAR_2, (byte) VAR_3, (byte) VAR_4, (byte) VAR_5,
			(byte) VAR_6, (byte) VAR_7, (byte) VAR_8, (byte) VAR_9,
			(byte) VAR_10};

	public static final byte[] VIEW_EDIT_OPEN_BROWSER_POINTER_SUMMARY = {
		(byte) VAR_51};
}
