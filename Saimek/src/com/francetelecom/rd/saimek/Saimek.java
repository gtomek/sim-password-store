package com.tomek.rd.saimek;

/*
 * Imported packages
 */
import sim.toolkit.*;
import sim.access.*;
import sun.security.krb5.internal.crypto.b;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class Saimek extends javacard.framework.Applet implements
		ToolkitInterface, ToolkitConstants, SaimekConstants {
	// Mandatory variables
	private SIMView gsmFile;
	private ToolkitRegistry reg;
	
	/**
	 * Users PIN code used for encryption of local data later
	 */
	private OwnerPIN pin;
	
	/**
	 * Temporary buffers
	 */
	// Temporary PIN numbers (initialised in constructor in non persistent memory)
	private static byte[] tempPinNumber;
	private static byte[] newPinBuffer;
	
	// Temporary account number (initialised in constructor in non persistent memory)
	private static byte[] tempAccountNumber;
	
	/**
	 * The key to be used for authentication
	 */
	private static DESKey authenticationLocalDataKey;
	
	/**
	 * @tempBytesBuffer : temporary bytes buffer to setup the minimum length and
	 *                  maximum length (TLV TAG)
	 */
	private static byte[] tempBytesBuffer ;
	/**
	 * This is a shared buffer which is used temporary for sending/receiving
	 * an SMS text
	 */
	private static byte[] tempSMSSendingBuffer;  //= new byte[260];
	
	/**
	 * This is a buffer used to compose a body of the message to be sent
	 */
	private static byte[] smsBodyBuffer; //= new byte[140];
	
	/**
	 * Temp buffers used for encryption
	 */
	private static byte[] tempEncryptBuffer;
	
	private static byte[] isAutomaticPinActive;
	
	/**
	 * This variable contains the SMSC number value
	 * 
	 * <p><b>NOTE_SMSC </b>: this number is retrieved from the 3F00/7F10/6F42 file (Short
	 *       Message Service Parameters) record number one.</p>
	 * @LV_Coding L:Length + V:Value (i.e. TON/NPI + SMSC NUMBER)
	 * @maximum value is 12 bytes (L + TON/NPI + 10 bytes)
	 */
	private static byte[] SMSserviceCenterAddress = new byte[12];
	
	/**
	 * Constructor of the applet
	 */
	public Saimek() {
		
		// Get GSM application reference
		gsmFile = SIMSystem.getTheSIMView();
		// Get reference of applet ToolkitRegistry object
		reg = ToolkitRegistry.getEntry();
		
		//initialise the PIN code with tryLimit = 30 maxPINSize = 4;
		pin = new OwnerPIN ( (byte)30, (byte)4);
		pin.update(DEFAULT_PIN_CODE_NUMBER, (byte)0, (byte) DEFAULT_PIN_CODE_NUMBER.length);
		
		// Initialise STK menu
		short tempPointer = MENU_VARIABLES_POINTER_SUMMARY[VAR_34];
		reg.initMenuEntry(menuVariables, (short) (tempPointer + 3),
				(short) (menuVariables[(short) (tempPointer + 1)] - 1),
				PRO_CMD_SELECT_ITEM, false, (byte) 0, (short) 0);
		
		// Register to formatted SMS PP event 
		reg.setEvent(EVENT_FORMATTED_SMS_PP_ENV);
		// Register to profile download event
		reg.setEvent(EVENT_PROFILE_DOWNLOAD);
		
		// Initialise variables in volatile memory
		tempPinNumber = JCSystem.makeTransientByteArray((short) 4,
				JCSystem.CLEAR_ON_RESET);
		newPinBuffer = JCSystem.makeTransientByteArray((short) 11,
				JCSystem.CLEAR_ON_RESET);
		tempAccountNumber = JCSystem.makeTransientByteArray((short) 1,
				JCSystem.CLEAR_ON_RESET);
		tempBytesBuffer = JCSystem.makeTransientByteArray((short) 2,
				JCSystem.CLEAR_ON_RESET);
		smsBodyBuffer = JCSystem.makeTransientByteArray((short) 140,
				JCSystem.CLEAR_ON_RESET);
		tempSMSSendingBuffer = JCSystem.makeTransientByteArray((short) 260,
				JCSystem.CLEAR_ON_RESET);
		tempEncryptBuffer = JCSystem.makeTransientByteArray((short) 64,
				JCSystem.CLEAR_ON_RESET);
		isAutomaticPinActive = JCSystem.makeTransientByteArray((short) 1,
				JCSystem.CLEAR_ON_RESET);
		
		// Create DES encryption key
		try {
			authenticationLocalDataKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, true);
		} catch(CryptoException ce) {
			// It is launched if the card does not support DES CryptoException.NO_SUCH_ALGORITHM
			ISOException.throwIt((short) 0x6A81);
		}
	}
	
	/**
	 * Method called by the JCRE at the installation of the applet
	 * @param bArray the byte array containing the AID bytes
	 * @param bOffset the start of AID bytes in bArray
	 * @param bLength the length of the AID bytes in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// Create the Java SIM toolkit applet
		Saimek StkCommandsExampleApplet = new Saimek();
		// Register this applet
		StkCommandsExampleApplet.register(bArray, (short) (bOffset + 1),
				(byte) bArray[bOffset]);
	}
	
	/**
	 * Method called by the SIM Toolkit Framework
	 * @param event the byte representation of the event triggered
	 */
	public void processToolkit(byte event) {
		EnvelopeHandler envHdlr = EnvelopeHandler.getTheHandler();

		if (event == EVENT_PROFILE_DOWNLOAD){
			// Get SMSC number
			getSmsCenterServiceNumber();
			isAutomaticPinActive[0] = FALSE; 
		}
		
		if (event == EVENT_FORMATTED_SMS_PP_ENV){
			processReceivedSMSMessage();
		}
		
		// Manage the request following the Timer Expiration event type
		if (event == EVENT_TIMER_EXPIRATION) {
			isAutomaticPinActive[0] = FALSE;
			// Find the TIMER_ID value and get id. of expired timer
			envHdlr.findTLV(TAG_TIMER_IDENTIFIER, (byte)0x01);
			byte bTimerId = envHdlr.getValueByte((short) 0);

			// Release the timer
			reg.releaseTimer(bTimerId);
		}
		
		// Manage the request following the MENU SELECTION event type
		if (event == EVENT_MENU_SELECTION) {
			
			// Check PIN
			if (!verifyPINCode(VAR_39, false)){
				// Display confirmation message
				displayConfirmationText(VAR_43);
				return;
			}
			
			// Set Encryption Key
			setEncryptionKey();
			
			//enter main menu loop
			while (1 > 0) {
				byte menuResult = 0;
				menuResult = displayMenuOption(MAIN_MENU_POINTER_SUMMARY, VAR_34, false);
				if ((menuResult == BACK_SELECTION) || (menuResult == 0x00) || (menuResult == VAR_33)
						|| (menuResult == RES_CMD_PERF_NO_RESP_FROM_USER))
					return;
				else {
					if ((menuResult >= VAR_1) && (menuResult <= VAR_10)){
						
						//store the account number in a temporary variable
						tempAccountNumber[0] = menuResult;
						
						// display the logins menu and call the function again with new value
						menuResult = displayMenuOption(VIEW_EDIT_OPEN_BROWSER_POINTER_SUMMARY, VAR_34, false);
					}
					
					// Edit Account Name option selected
					if (menuResult == VAR_37)
						menuResult = displayMenuOption(ACCOUNT_NAMES_POINTER_SUMMARY, VAR_37, true);
					
					// Browse your websites option selected
					if (menuResult == VAR_54){
							menuResult = displayMenuOption(ACCOUNT_NAMES_POINTER_SUMMARY, VAR_54, true);
							//store the account number in a temporary variable
							tempAccountNumber[0] = menuResult;
							menuResult = displayMenuOption(VIEW_EDIT_OPEN_BROWSER_POINTER_SUMMARY, VAR_34, false);
						}
					
					if (itemDecisionSelection(menuResult) == TERMINATE_SESSION_SELECTION)
						return;
				}
			}
		}
	}
	
	
	
	/**
	 * <b> setEncryptionKey </b>
	 * 
	 * @return true if success, false if error
	 */
	private boolean setEncryptionKey(){
		
		byte[] tempEncryptionKey = {
				(byte)0, (byte)0, (byte)0, (byte)0, (byte)0, 
				(byte)0, (byte)0, (byte)0, (byte)0, (byte)0, 
				(byte)0, (byte)0, (byte)0, (byte)0, (byte)0,
				(byte)0, (byte)0, (byte)0, (byte)0, (byte)0,
				(byte)0, (byte)0, (byte)0, (byte)0}; 
		
		Util.arrayCopy(tempPinNumber, (short) 0, tempEncryptionKey, (short) 1,
				(short)tempPinNumber.length);
		Util.arrayCopy(tempPinNumber, (short) 0, tempEncryptionKey, (short) 8,
				(short)tempPinNumber.length);
		
		try{
			authenticationLocalDataKey.setKey(tempEncryptionKey, (short)0);
		}
		catch(CryptoException ce){
			ISOException.throwIt((short) 0x6F99);
			return false;
		}
		
		return true;
	}
	
	
	
	/**
	 * <b> itemDecisionSelection </b>
	 * @param menuResult Number of a selected menu item
	 * @return
	 */
	private byte itemDecisionSelection(byte menuResult) {

	switch (menuResult) {

		case VAR_31: // Send Logins
			sendLogins();
			return BACK_SELECTION;
			
		case VAR_32:
			requestLogins();
			return TERMINATE_SESSION_SELECTION;
			
		case VAR_38:
			ChangePINNumber();
			return BACK_SELECTION;
			
		case VAR_50:
//			openBrowser((byte)(tempAccountNumber[0] + VAR_40));
//			tempAccountNumber[0] = (byte) 0;
			return TERMINATE_SESSION_SELECTION;
			
		case VAR_51: //display the login & password for the account
			byte[] tempMenuItems = { (byte) 0, (byte) 0 };
			tempMenuItems[0] = (byte) (VAR_11 + ((byte) 2 * ((byte) tempAccountNumber[0] - (byte) 1)));
			tempMenuItems[1] = (byte) (VAR_12 + ((byte) 2 * ((byte) tempAccountNumber[0] - (byte) 1)));
			//tempMenuItems[2] = (byte) (VAR_41 + ((byte) tempAccountNumber[0] - (byte) 1));
			
			//clear temp variable
			tempAccountNumber[0] = (byte) 0;
			
			//TODO Decrypt variables and display them
			
			menuResult = displayMenuOption(tempMenuItems, VAR_51, false);
			
			return itemDecisionSelection(menuResult);
			
		case VAR_56:
			activateAutomaticPin();
		
		default:
			
			 // Logins & Passwords 
			if ((menuResult >= VAR_11) && (menuResult <= VAR_30)){
				if ((menuResult % 2) != 0){
					// Logins Menu for VAR_11, VAR_13, VAR_15, VAR_17, VAR_19, VAR_21
					if (displayGetInput(VAR_35, MENU_VARIABLES_POINTER_SUMMARY[menuResult], VAR_44) != BACK_SELECTION)
						displayConfirmationText(VAR_52);
				}else{
					// Passwords Menu for VAR_12, VAR_14, VAR_16, VAR_18, VAR_20, VAR_22
					if (displayGetInput(VAR_36, MENU_VARIABLES_POINTER_SUMMARY[menuResult], VAR_44) != BACK_SELECTION)
						displayConfirmationText(VAR_52);
				}
			}
			// Account names
			if ((menuResult >= VAR_1) && (menuResult <= VAR_10))
				if (displayGetInput(VAR_37, MENU_VARIABLES_POINTER_SUMMARY[menuResult], VAR_44) != BACK_SELECTION)
					displayConfirmationText(VAR_52);
			
		return BACK_SELECTION;
		}
	
	}

	
	private void activateAutomaticPin() {
		// TODO Auto-generated method stub
		if (displayConfirmationQuestion(VAR_57))
			//check the PIN
			if (!verifyPINCode(VAR_39, false)){
				displayConfirmationText(VAR_43);
				return;
			}
		
		// setup automatic PIN timer
		setupAutomaticPinTimer();
		
	}



	/**
	 * <b>sendLogins</b> method used to send encrypted logins information to IP-SIM proxy
	 * Successful 
	 * 
	 */
	
	private void sendLogins() {
		
		byte i = 0;
		boolean isSendLoginsSuccessful = false;
		for (i = 0; i < VAR_10; i++){
			isSendLoginsSuccessful = sendLoginCredentials(i, ACTION_SEND_LOGINS_BACKUP);
		}
		if (isSendLoginsSuccessful)
			displayConfirmationText(VAR_47);
	}
	


	/**
	 *  <b>requestLogins</b> Method used to request logins backup retrieval 
	 *  from the IP-SIM proxy 
	 */
	
	private void requestLogins() {
		
		// re-set the SMS buffer
		Util.arrayFillNonAtomic(smsBodyBuffer, (short) 0,
				(short) smsBodyBuffer.length, (byte) 0x00);
		
		// Define message type
		smsBodyBuffer[0] = ACTION_REQUEST_LOGINS_BACKUP;
		
		// Send the message
		sendSMS(smsBodyBuffer, (short)smsBodyBuffer.length,
				SMS_DESTINATION_NUMBER, (short)SMS_DESTINATION_NUMBER.length);
		
	}
	
	
	
	/**
	 * <b>encryptAllLoginsAndPasswords</b>
	 */
	private void encryptAllLoginsAndPasswords(){
		byte i = 0;
		for (i = VAR_11; i < VAR_31; i++){
		}
		encryptMessagesUsingDes(i);
	}
	
	
	
	/**
	 * <b>decryptAllLoginsAndPasswords</b>
	 */
	private void decryptAllLoginsAndPasswords(){
		byte i = 0;
		for (i = VAR_11; i < VAR_31; i++){
			decryptMessageUsingDes(i);
		}
	}
	
	
	/**
	 * <b>encryptMessages</b> Method used to encrypt logins and passwords 
	 * @param websiteId ID of the website entry
	 */
	
	private void encryptMessagesUsingDes(byte websiteId){
		
		Cipher cipher;
		
		// set encryption key
		short inputVariableOffset = (short) (MENU_VARIABLES_POINTER_SUMMARY[websiteId]);
		short inputVariableDataOffset = (short) (inputVariableOffset + (short) 3);
		short variableLength = 
			(short) (menuVariables[(short) (inputVariableOffset + (short) 1)] - (short) 1);
		
		// Replace any previous cause values with values 0x00
		Util.arrayFillNonAtomic(tempEncryptBuffer, (short) 0,
				(short) tempEncryptBuffer.length, (byte) 0xFF);	
		Util.arrayCopy(menuVariables, inputVariableDataOffset, tempEncryptBuffer, 
				(short) 0, variableLength);
		
		try{
			//Cipher the logins data
			cipher = Cipher.getInstance(CRYPTO_ALGORITHM_TYPE, false);
			cipher.init(authenticationLocalDataKey, Cipher.MODE_ENCRYPT);
			// we take only x8 bytes because the array length must divide by 8...
			cipher.doFinal(tempEncryptBuffer, (short) 0, variableLength, 
					menuVariables, inputVariableDataOffset);
		}
		catch (CryptoException ce){
			if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				displayMessage(ERROR_NOT_SUPPORTED, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				displayMessage(ERROR1, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_USE)
				displayMessage(ERROR2, (short) 0);
		}
		catch (Exception exception){
			displayMessage(ERROR3, (short) 0);
		}
	}

	
	
	/**
	 * 
	 * @param itemId
	 * @param outputBuffer needs to contain 2 extra bytes at the beginning
	 *        1st - item length, 2nd - item ID (VAR_xx) followed by the 
	 *        message content
	 * @return true for success, false for failure
	 */
	
	private boolean encryptMessagesUsingDes(byte itemId, byte[] outputBuffer){
		
		Cipher cipher;
		
		// set encryption key
		short inputVariableOffset = (short) (MENU_VARIABLES_POINTER_SUMMARY[itemId]);
		short inputVariableDataOffset = (short) (inputVariableOffset + (short) 3);
		short variableLength = 
			(short) (menuVariables[(short) (inputVariableOffset + (short) 1)] - (short) 1);
		
		// Insert length to input variable
		outputBuffer[0] = (byte) variableLength;
		// Insert item  ID to input variable
		outputBuffer[1] = itemId; 
		
		try{
			// Cipher the logins data
			cipher = Cipher.getInstance(CRYPTO_ALGORITHM_TYPE, false);
			cipher.init(authenticationLocalDataKey, Cipher.MODE_ENCRYPT);
			// We take only x8 bytes because the array length must divide by 8
			// if we do not use padding
			cipher.doFinal(menuVariables, inputVariableDataOffset, 
					variableLength, outputBuffer, (short) 2);
			
			// Update the menuVariables with the encrypted values
			Util.arrayCopy(outputBuffer, (short) 2, menuVariables, 
					inputVariableDataOffset, variableLength);
			return true;
		}
		catch (CryptoException ce){
			if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				displayMessage(ERROR_NOT_SUPPORTED, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				displayMessage(ERROR1, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_USE)
				displayMessage(ERROR2, (short) 0);
		}
		catch (Exception exception){
			displayMessage(ERROR3, (short) 0);
		}
		
		return false;
	}
	
	
	
	/**
	 * Method decrypts the inputBuffer value and puts it to the menuVariables
	 * array entry identified by input itemId
	 * 	
	 * @param itemId
	 * @param inputBuffer
	 */
	
	private boolean decryptMessageUsingDes(byte itemId, byte[] inputBuffer){
		
		Cipher cipher;		
		
		short outputVariableOffset = (short) (MENU_VARIABLES_POINTER_SUMMARY[itemId]);
		short outputVariableDataOffset = (short) (outputVariableOffset + 3);
		short variableLength = 
			(short) (menuVariables[(short) (outputVariableOffset + (short) 1)] - (short) 1);
		
		try{
			cipher = Cipher.getInstance(CRYPTO_ALGORITHM_TYPE, false);
			cipher.init(authenticationLocalDataKey, Cipher.MODE_DECRYPT);
			cipher.doFinal(inputBuffer, (short) 2, (short) variableLength, 
					menuVariables, outputVariableDataOffset);
		}
		catch (CryptoException ce){
			if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				displayMessage(ERROR_NOT_SUPPORTED, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				displayMessage(ERROR3, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_USE)
				displayMessage(ERROR4, (short) 0);
		}
		
		return false;		
	}
	
	
	/**
	 * Method decrypts an item in menuVariables array taking as an input only
	 * item id
	 * @param itemId
	 * @return
	 */
	private boolean decryptMessageUsingDes(byte itemId){
		
		Cipher cipher;		
		
		short outputVariableOffset = (short) (MENU_VARIABLES_POINTER_SUMMARY[itemId]);
		short outputVariableDataOffset = (short) (outputVariableOffset + 3);
		short variableLength = 
			(short) (menuVariables[(short) (outputVariableOffset + (short) 1)] - (short) 1);
		
		// Replace any previous cause values with values 0x00
		Util.arrayFillNonAtomic(tempEncryptBuffer, (short) 0,
				(short) tempEncryptBuffer.length, (byte) 0xFF);	
		Util.arrayCopy(menuVariables, outputVariableDataOffset, tempEncryptBuffer, 
				(short) 0, variableLength);
		
		try{
			cipher = Cipher.getInstance(CRYPTO_ALGORITHM_TYPE, false);
			cipher.init(authenticationLocalDataKey, Cipher.MODE_DECRYPT);
			cipher.doFinal(tempEncryptBuffer, (short) 0, (short) variableLength, 
					menuVariables, outputVariableDataOffset);
		}
		catch (CryptoException ce){
			if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				displayMessage(ERROR_NOT_SUPPORTED, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				displayMessage(ERROR3, (short) 0);
			if (ce.getReason() == CryptoException.ILLEGAL_USE)
				displayMessage(ERROR4, (short) 0);
		}
		
		return false;		
	}

	
	/**
	 * Method not in use
	 * @param websiteId
	 */
	
	private void encryptMessagesUsingSha(byte websiteId){
		
		MessageDigest sha; 
		byte loginsId = (byte)(websiteId + VAR_10);
		byte passwordsId = (byte)(websiteId + VAR_11);
		
		// get logins variables offset
		short inputVariableOffset = (short)(MENU_VARIABLES_POINTER_SUMMARY[loginsId]);
		
		try{
			sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			sha.doFinal(menuVariables, (short)(inputVariableOffset + (short)3), 
					(short)(menuVariables[(short)(inputVariableOffset + (short)1)] - (short)1),
					tempEncryptBuffer, (short) 0);
		}
		catch (CryptoException cexception){
			if (cexception.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				displayMessage(ERROR_NOT_SUPPORTED, (short) 0);
			if (cexception.getReason() == CryptoException.ILLEGAL_VALUE)
				displayMessage(ERROR1, (short) 0);
			if (cexception.getReason() == CryptoException.ILLEGAL_USE)
				displayMessage(ERROR2, (short) 0);
		}
	}
	
	
	/**
	 * <b> ChangePINNumber </b> Method used to change PIN number
	 */
	
	private void ChangePINNumber() {
		if (verifyPINCode(VAR_40, false)){
			if (verifyPINCode(VAR_41, true))
				if (!verifyPINCode(VAR_42, true))
					displayConfirmationText(VAR_43);
				else
					displayConfirmationText(VAR_52);
		} else
			displayConfirmationText(VAR_43);
		
	}
	
	
	
	/**
	 * <b> displayMenuOption</b> is a method which constructs the menu selection
	 *                    PROACTIVE command. Depending on the title ID, this
	 *                    method will append different items. 
	 * <p><b> NOTE_DMO1</b> Maximum length of select item EditHandler buffer is FFh
	 * 				you cannot exceed it, it is is higher there will be an exception
	 * 				ToolkitException.HANDLER_OVERFLOW thrown. In this case 
	 * 				please limit the total length of menu items. Otherwise
	 * 				this method will cut the length of each item up to 20bytes
	 * 				(19 characters + 1id) </p>
	 *   	  
	 * @param menuItemsId
	 *            : this is a buffer which contains all items references to be
	 *            displayed in the menu selection
	 * @param enforceMaxLength :if true this variable enforces max length of a menu entry
	 * 				up to 19 characters + 1 entry length 
	 * @return itemIdentifier selected or back_selection value
	 */
	
	private byte displayMenuOption(byte[] menuItemsId, byte menuTitleId, boolean enforceMaxLength) {

		// initialise some local temp variables
		byte attempts = (byte) 0x00;
		byte generalResultResponse = (byte) 0x00;
		byte itemIdentifier = (byte) 0x00;
		byte menuItemsIdElem = menuItemsId[0];
		byte tempMenuItemSize = (byte) 0x00;
		short menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[menuItemsIdElem];
		ProactiveHandler proHdlr = null;
		ProactiveResponseHandler ProRespHdlr = null;

		// STARTING TO BUILD THE SELECT ITEM PROACTIVE COMMAND
		try {
			proHdlr = ProactiveHandler.getTheHandler();
			
			//initialise proactive command
			proHdlr.init(PRO_CMD_SELECT_ITEM, (byte) 0x00, (byte) 0x82);
			
			// APPEND THE TLV TITLE
			proHdlr
					.appendTLV(
							TAG_ALPHA_IDENTIFIER,
							menuVariables,
							(short) (MENU_VARIABLES_POINTER_SUMMARY[menuTitleId] + 3),
							(short) (menuVariables[(short) (MENU_VARIABLES_POINTER_SUMMARY[menuTitleId] + 1)] - 1));
	
			// create the options
			for (byte i = VAR_1; i <= (short) (menuItemsId.length & 0xFF); i = (byte) (i + 1)) {
				menuItemsIdElem = menuItemsId[i - (byte)1];
				menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[menuItemsIdElem];
				
				// check if length of each item exceeds 20 bytes and cuts it to 20
				// to prevent from handler overflow
				tempMenuItemSize = (byte) (menuVariables[(short) (menuItemPointerElem + 1)]);
				if (enforceMaxLength & (tempMenuItemSize > (byte)20))
					tempMenuItemSize = 20;
				
				// append the Menu Item to pro-active command
				proHdlr.appendTLV((byte) 0x8F, menuVariables,
						(short) (menuItemPointerElem + 2),
						tempMenuItemSize);
			}// end of for
	
			// The method sends PROACTIVE command to the ME and waits for 
			// general result
			generalResultResponse = proHdlr.send();
			
			// <b> NOTE_DMO2 </b> : this line solves the issue that we had with some Nokia
			// devices. E.G. NOKIA PRISMA does not display the menu when
			// pressing the red key button (i.e. result = 0x20h,0x01h), however,if
			// the method tries again to send the same PROACTIVE command it will
			// work.
			while (generalResultResponse == (byte) 0x20 & attempts < (byte) 0x03) {
				generalResultResponse = proHdlr.send();
				// We allow three maximum attempts
				attempts++;
			}// end of while
			
		} catch (ToolkitException te) {
			
			// display error message
			displayConfirmationText(VAR_49);
			return BACK_SELECTION;
		}
		

		// If the menu has been displayed, the method analyses the TR:
		// The result can be a "Back request" or a "menu selection identifier"
		try {
			ProRespHdlr = ProactiveResponseHandler.getTheHandler();
		} catch (ToolkitException te) {
			return BACK_SELECTION;
		}// end of catch

		// check if user didn't press back or cancel button
		// if not get the selected item
		if ((generalResultResponse != RES_CMD_PERF_BACKWARD_MOVE_REQ)
				&& (generalResultResponse != RES_CMD_PERF_SESSION_TERM_USER)) {
			try {
				itemIdentifier = (byte) ProRespHdlr.getItemIdentifier();
				return itemIdentifier;
			} catch (ToolkitException te) {
			}
		}

		if (generalResultResponse == RES_CMD_PERF_NO_RESP_FROM_USER)
			return RES_CMD_PERF_NO_RESP_FROM_USER;

		return BACK_SELECTION;

	}// end of method

	
	
	/**
	 * <b> processReceivedSMSMessage </b> method is called when a formatted SMS message 
	 * 	arrives to the card. It will read the content of the message and pass it to
	 *  a parsing method for further treatment  
	 * 
	 * @return boolean true if reception of the message went fine, false otherwise
	 */
	
	private boolean processReceivedSMSMessage() {
		
		// get the envelope handler
		EnvelopeHandler envHdlr ;
		try {
			envHdlr = EnvelopeHandler.getTheHandler();
		} catch (ToolkitException e) {
			displayConfirmationText(VAR_49);
			return false;
		}
		
		// Replace any previous cause values with values 0x00
		Util.arrayFillNonAtomic(smsBodyBuffer, (short) 0,
				(short) smsBodyBuffer.length, (byte) 0xFF);
		
		if (envHdlr.getSecuredDataLength() != 0){
			try{
				// get received data 
				envHdlr.copyValue((short)envHdlr.getSecuredDataOffset(), smsBodyBuffer, (short)0,
						(short)envHdlr.getSecuredDataLength());
			} catch (ToolkitException te){
				if (te.getReason() == ToolkitException.OUT_OF_TLV_BOUNDARIES)
					displayConfirmationText(VAR_49);
				return false;
			}

			// parse the data and save it in the persistent memory
			parseReceivedData();
			return true;
		} else {
			displayConfirmationText(VAR_49);
		}
		
		return false;
	}

	
	
	/**
	 * <b> parseReceivedData </b> method is called when a received SMS message needs to be 
	 * 	parse and the an action described in the message needs to be executed 
	 * @param tempReceiveSMSBuffer a buffer containing the message to be parsed
	 */
	private void parseReceivedData(){
		
		// message format
		// 1 byte message type
		// 1 byte entry position
		// 1 byte URL length 
		// n bytes URL body
		// 1 byte Login rname length 
		// n bytes Login name body
		// 1 byte Password length 
		// n bytes Password body
		

		// action type (described in constants file) 
		byte actionType = smsBodyBuffer[0];
		//position of the item to update
		byte itemPossition = (byte)(smsBodyBuffer[1] - 0x30);

		switch (actionType){
		
			// Received action to store credentials received from the server
			case ACTION_STORE_CREDENTIALS:
				storeLoginCredentials(itemPossition);
				// TODO Received logins are unencrypted and need to be encrypted
				// encryptMessagesUsingDes(itemPossition);
				
				break;
				
			// Received request to retrieve credentials from the card
			case ACTION_RETRIEVE_CREDENTIALS:
				//check the PIN
				if (!(isAutomaticPinActive[0] == TRUE))
					if (!verifyPINCode(VAR_39, false)){
						displayConfirmationText(VAR_43);
						break;
					}
				if (sendLoginCredentials((byte)(itemPossition), 
						ACTION_RETRIEVE_CREDENTIALS))
					displayConfirmationText(VAR_47);
				
				break;

			// Received backed-up logins
			case ACTION_REQUEST_LOGINS_BACKUP:
				// Store the logins
				// Received logins should be already encrypted
				storeLoginCredentials(itemPossition);
				break;
			default:
			 	break;
		}
	}
	
	
	
	/**
	 * <b>sendLoginCredentials</b> method sends logins information
	 * to IP-SMS gateway
	 * 
	 * @param itemPossition position of the website in the SIM memory
	 */
	
	private boolean sendLoginCredentials(byte itemPossition, byte actionType) {
		
		// re-set the SMS buffer
		Util.arrayFillNonAtomic(smsBodyBuffer, (short) 0,
				(short) smsBodyBuffer.length, (byte) 0x00);
		
		// compose new message
		// message type
		smsBodyBuffer[0] = actionType;
		// position
		smsBodyBuffer[1] = (byte)(itemPossition + 0x30);
		// URL length
		short menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[(short)(itemPossition + 1)];
		byte urlTempUrlLength = (byte)(menuVariables[(short)(menuItemPointerElem + 1)] - 1);
		smsBodyBuffer[2] = (byte)(urlTempUrlLength + LENGTH_CONVERTER_VALUE);

		// URL value
		Util.arrayCopy(menuVariables, (short)(menuItemPointerElem + 3), 
				smsBodyBuffer, (short)3, (short)urlTempUrlLength);
		
		// logins length
		menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[(short)(2 * itemPossition + VAR_11)];
		byte tempLoginsLength = (byte)(menuVariables[(short)(menuItemPointerElem + 1)] - 1);
		smsBodyBuffer[(byte)(urlTempUrlLength + 3)] = (byte)(tempLoginsLength + LENGTH_CONVERTER_VALUE);
		
		// logins
		Util.arrayCopy(menuVariables, (short)(menuItemPointerElem + 3), 
				smsBodyBuffer, (short)(urlTempUrlLength + 4), (short)tempLoginsLength);
		
		// password length
		menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[(short)(2 * itemPossition + VAR_12)];
		byte tempPasswordLength = (byte)(menuVariables[(short)(menuItemPointerElem + 1)] - 1);
		smsBodyBuffer[(byte)(urlTempUrlLength + tempLoginsLength + 4)] = (byte)(tempPasswordLength + LENGTH_CONVERTER_VALUE);
		// password
		Util.arrayCopy(menuVariables, (short)(menuItemPointerElem + 3), 
				smsBodyBuffer, (short)(urlTempUrlLength + tempLoginsLength + 5), (short)tempPasswordLength);
		
		return sendSMS(smsBodyBuffer, (short)smsBodyBuffer.length,
				SMS_DESTINATION_NUMBER, (short)SMS_DESTINATION_NUMBER.length);
	}
	
	
	/**
	 * 
	 * @param itemPossition
	 */

	private void storeLoginCredentials(byte itemPossition) {
		
		// dispaly reception confirmation
		displayConfirmationText(VAR_48);
		// initialise temporary variables
		byte urlNameLength = (byte)(smsBodyBuffer[2] - LENGTH_CONVERTER_VALUE);
		byte loginNameLength = (byte)((smsBodyBuffer[(byte)urlNameLength + (byte)3]) - 
				LENGTH_CONVERTER_VALUE);
		byte userPasswordLength = (byte)((smsBodyBuffer[(byte)(loginNameLength + 
				urlNameLength + (byte)4)]) - LENGTH_CONVERTER_VALUE);
		// for look helper variable
		byte i = 0;
		
		// update URL name in menuVariables array
		short menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[(short)(itemPossition + 1)];
		// length needs to be increased by 1 for the identifier of the menu item 
		// in select item pro-active command
		menuVariables[(short)(menuItemPointerElem + 1)] = (byte)(urlNameLength + 1);
		Util.arrayCopy(smsBodyBuffer, (short)3, menuVariables, (short)(menuItemPointerElem + 3), urlNameLength);
	
		// update login Name in menuVariables array
		menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[(short)(2 * itemPossition + VAR_11)];
		menuVariables[(short)(menuItemPointerElem + 1)] = (byte)(loginNameLength + 1);
		Util.arrayCopy(smsBodyBuffer, (short)(urlNameLength + 4), menuVariables, (short)(menuItemPointerElem + 3), loginNameLength);
		
		// update password in menuVariables array
		menuItemPointerElem = (short) MENU_VARIABLES_POINTER_SUMMARY[(short)(2 * itemPossition + VAR_12)];
		menuVariables[(short)(menuItemPointerElem + 1)] = (byte)(userPasswordLength + 1);
		Util.arrayCopy(smsBodyBuffer, (short)(loginNameLength + urlNameLength + 5), menuVariables, (short)(menuItemPointerElem + 3), userPasswordLength);
		
	}

	
	
	/***************************************************************************
	 * @getSMSCenterServiceNumber method is used to retrieved the SMS service
	 *                            number from the SIM file 6F42 in the 3F00/7F10
	 *                            directory. If no number can be founded, then
	 *                            ICM will try to send the SMS without any SMSC
	 *                            number
	 * @return void
	 */
	private void getSmsCenterServiceNumber() {
		try {
			gsmFile.select((short) 0x3F00);
			gsmFile.select((short) 0x7F10);
			gsmFile.select((short) 0x6F42);
		} catch (SIMViewException e) {
		}
		try {
			// we read the first record of the file 6F42, and then stores the
			// SMS service centre address into the SMSserviceCenterAddress
			// buffer
			gsmFile.readRecord((short) 0x0001,
					(byte) SIMView.REC_ACC_MODE_ABSOLUTE_CURRENT, (short) 25,
					SMSserviceCenterAddress, (short) 0, (short) 12);
		} catch (SIMViewException e) {
		}
	}// end of private void getSMSCenterServiceNumber() 
	
	
	
	/**
	 * @sendSMS is defined to send an SMS text to the calling party.
	 * 
	 * <p><b> NOTE_SS1</b> We decided to remove the alpha identifier because it is not
	 *       interpreted by SAMSUNG device </p>
	 * 
	 * <p><b> NOTE_SS2</b> : the SMS packing is not performed by the ME, but by ICM </p>
	 * 
	 * @param buffer :
	 *            the text buffer to be sent to the calling party.
	 * @param bufferLength :
	 *            the length of the text buffer
	 * 
	 * @param dialledDigitBufferLocal :
	 * 
	 * @param dialledDigitsLenghtLocal :
	 * 
	 */

	public boolean sendSMS(byte[] buffer, short bufferLength,
			byte[] dialledDigitBufferLocal, short dialledDigitsLenghtLocal) {

		//clear temp buffer
		Util.arrayFillNonAtomic(tempSMSSendingBuffer, (short) 0, (short)tempSMSSendingBuffer.length, (byte)0xFF);
		short offset = (short) 0;
		short temp = (short) 0;
		// ICM starts to build the PROACTIVE command
		ProactiveHandler proHdlr = ProactiveHandler.getTheHandler();
		proHdlr.init(PRO_CMD_SEND_SHORT_MESSAGE, (byte) 0x00, DEV_ID_NETWORK);

		try {// This is the TLV TAG ADDRESS value
			proHdlr.appendTLV(TAG_ADDRESS, SMSserviceCenterAddress, (short) 1,
					(short) (SMSserviceCenterAddress[0]));
		} catch (Exception e) {
			// if the SMSserviceCenterAddress is not defined, then ICM will try
			// to send the SMS with no Service Centre Number value
		}// end of catch

		// The method constructs the SMS header by appending the first
		// parameter
		Util.arrayCopy(SMS_TPDU_TLV_1_part, (short) 0, tempSMSSendingBuffer,
				(short) 0, (short) SMS_TPDU_TLV_1_part.length);

		offset += (short) SMS_TPDU_TLV_1_part.length;

		// Length parameters, for that we have to check how many digits
		// -1 because we have to remove the TON/NPI value
		byte lastNumber = (byte) dialledDigitBufferLocal[(short) (dialledDigitsLenghtLocal - 1)];
		temp = (short) ((dialledDigitsLenghtLocal - 1) * 2);
		// we compare the last digit, if this one is odd then we update the
		// length value
		if (lastNumber >= (byte) 0xF0 && lastNumber <= (byte) 0xF9)
			temp--;

		// We copy the first byte of the temp value into the tempBytesBuffer
		Util.setShort(tempBytesBuffer, (short) 0, temp);
		Util.arrayCopy(tempBytesBuffer, (short) 1, tempSMSSendingBuffer, offset,
				(short) 1);
		offset += (short) 1;
		// we copy the destination address (i.e. calling party number)
		Util.arrayCopy(dialledDigitBufferLocal, (short) 0, tempSMSSendingBuffer,
				offset, dialledDigitsLenghtLocal);
		offset += dialledDigitsLenghtLocal; // we copy the first part

		short convertedLength;

		// check if message should be encoded on 7 or 8 bits
		
		// the method appends the remaining parameters
		Util.arrayCopy(SMS_TPDU_TLV_3_part_8bit, (short) 0,
				tempSMSSendingBuffer, offset,
				(short) SMS_TPDU_TLV_3_part_8bit.length);
		offset += SMS_TPDU_TLV_3_part_8bit.length;
		convertedLength = bufferLength;

		// User data length (8bit format)
		tempSMSSendingBuffer[offset] = (byte) bufferLength;
		offset += (short) 1;

		Util.arrayCopy(buffer, (short) 0, tempSMSSendingBuffer, offset,
					(short) convertedLength);

		offset += (short) convertedLength;
		// we copy the rest
		proHdlr.appendTLV((byte) 0x8B, tempSMSSendingBuffer, (short) 0,
				(short) offset);
		
		// add alpha identifier length zero to disable "sending message" popup on Symbian phones
		// for the reporting messages i.e. when the encoding is 8bit 
		proHdlr.appendTLV(TAG_ALPHA_IDENTIFIER, EMPTY,
	                (short) 0x00, (short) 0x00);
		
		if (proHdlr.send() == RES_CMD_PERF) {
//			if (confiamationMessageID != (byte) 0xFF)
				return true;
//				displayConfirmationText(confiamationMessageID);
		}// end of if
		return false;
	}// end of private byte sendSMS method
	
	
	
	/***************************************************************************
	 * @displayGetInput method is used to get a text input from the
	 *                           user and save it. This method takes four parameters,
	 *                           described below:
	 * 
	 * @param titleId :
	 *            this is the title reference to be used to append the TLV title
	 *            element.
	 * @param textReference :
	 *            this is the text reference to retrieve the value from the
	 *            srcBuffer parameter
	 * @return (short) 0x00FF : if the user presses the back button or the
	 *         length of the data copied into the destBuffer
	 */
	private short displayGetInput(byte titleId, short textReference, byte confirationMessageId){

		byte generalResultResponse = 0;
		byte[] tempBytesBuffer = {(byte)0, (byte)0};
		// temp variable used for copying received values
		byte[] tempBuffer = {(byte)0, (byte)0, (byte)0, (byte)0,(byte)0, 
				(byte)0,(byte)0, (byte)0,(byte)0, (byte)0, (byte)0,
				(byte)0, (byte)0, (byte)0, (byte)0,(byte)0, 
				(byte)0,(byte)0, (byte)0,(byte)0, (byte)0, (byte)0,
				(byte)0, (byte)0, (byte)0, (byte)0,(byte)0, 
				(byte)0,(byte)0, (byte)0,(byte)0, (byte)0, (byte)0,
				(byte)0, (byte)0, (byte)0, (byte)0,(byte)0, 
				(byte)0,(byte)0, (byte)0,(byte)0, (byte)0, (byte)0};
		short tempResponseLenght = 0;
		// Here we setup the minimum length (minimum user input)
		tempBytesBuffer[0] = (byte) 0x01;
		// Here we setup the maximum length (maximum input authorised), this
		// maximum value is retrieve from the srcBuffer with the text
		// reference.(Cf. IcmConstants class to understand how the buffer is
		// constructed)
		tempBytesBuffer[1] = (byte) (menuVariables[textReference] - 3);
		short tempTitlePosition = MENU_VARIABLES_POINTER_SUMMARY[titleId];
		// we start to build the PROACTIVE command
		ProactiveHandler proHdlr = ProactiveHandler.getTheHandler();
		// Qualifier : 0x01 : SMS default alphabet
		proHdlr.init(PRO_CMD_GET_INPUT, (byte) 0x01, (byte) 0x82);
		// TLV title : (we use the titleId reference position in the memory
		// buffer)
		proHdlr.appendTLV((byte) 0x8D, (byte) 0x04, menuVariables,
				(short) (tempTitlePosition + 3),
				(short) (menuVariables[(short) (tempTitlePosition + 1)] - 1));
		// ResponseLength TLV: we use the temporary buffer initialised at the
		// beginning of the method
		proHdlr.appendTLV((byte) 0x91, tempBytesBuffer, (short) 0,
				(short) tempBytesBuffer.length);
		// This is the default text value to be prompted to the end-user
		proHdlr.appendTLV((byte) 0x17, (byte) 0x04, menuVariables,
				(short) (textReference + 3),
				(short) ((short) (menuVariables[(short) (textReference + 1)] & 0xFF) - 1));
		// we send the PROACTIVE command
		proHdlr.send();
		// we have to get back the value
		ProactiveResponseHandler proRespHdlr = ProactiveResponseHandler
				.getTheHandler();
		// BACK OPTION
		generalResultResponse = proRespHdlr.getGeneralResult();
		if ((generalResultResponse == RES_CMD_PERF_BACKWARD_MOVE_REQ)
			|| (generalResultResponse == RES_CMD_PERF_SESSION_TERM_USER))
			return BACK_SELECTION;
		// we copy the input
		tempResponseLenght = proRespHdlr.findAndCopyValue((byte) 0x0D, tempBuffer, (short) 0);
		
		//verify if user wants to save it
		if (displayConfirmationQuestion(confirationMessageId)){
			menuVariables[(short) (textReference + 1)] = (byte) tempResponseLenght;
			Util.arrayCopy(tempBuffer, (short) 1, menuVariables,
					(short) (textReference + 3),
					(short) (tempResponseLenght - 1));
			return tempResponseLenght; 
		}else
			return BACK_SELECTION;
		
	}// end of displayGetInput method
	
	
	
	/**
	 * @verifyPINCode
	 * @return
	 */
	
	private boolean verifyPINCode(byte messageID, boolean isPINUpdateRequired) {
		
		byte[] responseLengthBuffer = {(byte)0, (byte)4};
//		byte[] newPinBuffer = {(byte)0, (byte)0, (byte)0, (byte)0,(byte)0, 
//				(byte)0,(byte)0, (byte)0,(byte)0, (byte)0, (byte)0};
		short tempTitlePosition = MENU_VARIABLES_POINTER_SUMMARY[messageID];
		// we start to build the PROACTIVE command
		ProactiveHandler proHdlr = ProactiveHandler.getTheHandler();
		// Qualifier : 0x04 :  hidden text
		proHdlr.init(PRO_CMD_GET_INPUT, (byte) 0x04, (byte) 0x82);
		// TLV title : (we use the titleId reference position in the memory
		// buffer)
		proHdlr.appendTLV((byte) 0x8D, (byte) 0x04, menuVariables,
				(short) (tempTitlePosition + 3),
				(short) (menuVariables[(short) (tempTitlePosition + 1)] - 1));
		// ResponseLength TLV: we use the temporary buffer initialised at the
		// beginning of the method
		proHdlr.appendTLV((byte) 0x91, responseLengthBuffer, (short) 0,
				(short) responseLengthBuffer.length);

		// we send the PROACTIVE command
		proHdlr.send();
		// we have to get back the value
		ProactiveResponseHandler proRespHdlr = ProactiveResponseHandler
				.getTheHandler();
		// we copy the input
		proRespHdlr.findAndCopyValue((byte) 0x0D, newPinBuffer, (short) 0);
		
		// Check if it is a PIN update or just verification
		if (isPINUpdateRequired){
			// check if the tempPINNumber is set
			if (tempPinNumber[0] == (byte) 0){
				//if not, copy the user typed-in value to the tempPinNumber value for further comparison
				Util.arrayCopy(newPinBuffer, (short) 1, tempPinNumber,(short) 0, (short) 4);
				return true;
			}
			
			// if tempPinNumber has been set already compare it with the just received value, 
			// and if it matches, update the pin
			if (Util.arrayCompare(newPinBuffer, (byte)1, tempPinNumber, (byte)0, (byte)4) == (byte) 0){			
				// update PIN
				pin.update(newPinBuffer, (byte)1, (byte)4);
				// reset the tempPINNumber
				tempPinNumber[0] = (byte) 0;
				return true;
			}  
			return false;
		}
		else{
			// compare the PIN number with the good one and return the result
			return pin.check(newPinBuffer, (byte)1, (byte)4);
		}
	
	}
	
	
	
	/**
	 * displayConfirmationQuestion method prompts a message to the user's screen
	 *                             and waits for the user to respond by 'yes' or
	 *                             'no'
	 * 
	 * @param messageId :
	 *            message reference to display in the confirmation message
	 * @pragam isConfirmationRequired           
	 * @return true if the user responds 'yes' to the confirmation message and
	 *         false if the user responds 'no'
	 */
	private boolean displayConfirmationQuestion(byte messageId) {
		
		byte[] tempBytesBuffer = {(byte) 0, (byte)0};
		
		short tempMessageIdPosition = MENU_VARIABLES_POINTER_SUMMARY[messageId];
		// we construct the question
		ProactiveHandler proHdlr = ProactiveHandler.getTheHandler();
		proHdlr.init(PRO_CMD_GET_INKEY, (byte) 0x04, (byte) 0x82);
		// title
		proHdlr.appendTLV((byte) 0x8D, (byte) 0x04, menuVariables,
				(short) (tempMessageIdPosition + 3),
				(short) (menuVariables[(short) (tempMessageIdPosition + 1)] - 1));
		proHdlr.send();

		ProactiveResponseHandler proRespHdlr = ProactiveResponseHandler
				.getTheHandler();

		proRespHdlr.findAndCopyValue((byte) 0x0D, tempBytesBuffer, (short) 0);
		// we analyse the result
		if (Util.arrayCompare(YES_RESPONSE, (short) 0, tempBytesBuffer,
				(short) 1, (short) 1) == (byte) 0x00)
			return true;
		else
			return false;

	}// end of private boolean displayConfirmationQuestion(short messageId) {
	
	
	
	/**
	 * displayConfirmationText displays confirmation text
	 * 
	 * @param messageId id of the message from menu variables array
	 * @return boolean
	 */
	private boolean displayConfirmationText(byte messageId){
		
		short tempMessageIdPosition = MENU_VARIABLES_POINTER_SUMMARY[messageId];
		// we construct the question
		ProactiveHandler proHdlr = ProactiveHandler.getTheHandler();
		proHdlr.init(PRO_CMD_DISPLAY_TEXT, (byte) 0x81, DEV_ID_DISPLAY);
		proHdlr.appendTLV((byte) 0x8D, (byte) 0x04, menuVariables,
				(short) (tempMessageIdPosition + 3),
				(short) (menuVariables[(short) (tempMessageIdPosition + 1)] - 1));
		proHdlr.send();
		
		return false;
	}// end of private boolean displayConfirmationText
	
	

	/**
	 * Method called by the JCRE, once selected
	 * @param apdu the incoming APDU object
	 */
	public void process(APDU apdu) {
		// ignore the applet select command dispached to the process
		if (selectingApplet()) {
			return;
		}
	}


	
	/**
	 * displayMessage: helper function to display some text <br>
	 * 				  to be removed from release if not needed
	 * 
	 * @param bytesToDisplay byte array of the data to display
	 */
	private void displayMessage(byte[] bytesToDisplay, short offset) {

		// Get the received envelope
		ProactiveHandler proHdlr = ProactiveHandler.getTheHandler();

		// Initialise the display text command
		proHdlr.initDisplayText((byte) 0x00, DCS_8_BIT_DATA, bytesToDisplay, offset,
				(short) (bytesToDisplay.length - offset));
		proHdlr.send();

		return;
	}
	
	
	/**
	 *  <b>setupAutomaticPinTimer</b> 
	 */
	
	private boolean setupAutomaticPinTimer(){
		
		ProactiveHandler proHdlr;
		byte bTimerId;
		
		// 1h timer value setup
//		byte[] timerValueTLV = { (byte) 0x10, (byte) 0x00, (byte) 0x00};
		byte[] timerValueTLV = { (byte) 0x00, (byte) 0x01, (byte) 0x00};
		
		try{
			// allocate timer for automatic PIN feature
			bTimerId = reg.allocateTimer();
			
			// Get the received envelope
			proHdlr = ProactiveHandler.getTheHandler();
			
			proHdlr.init(PRO_CMD_TIMER_MANAGEMENT , (byte)0x00, DEV_ID_ME );
			proHdlr.appendTLV(TAG_TIMER_IDENTIFIER , (byte)bTimerId);
			proHdlr.appendTLV(TAG_TIMER_VALUE , timerValueTLV, (byte)0, 
					(byte)timerValueTLV.length);
			//proHdlr.appendTLV(TAG_RESPONSE_LENGTH, (byte)0x01, (byte)0x01);
			proHdlr.send();
			
			isAutomaticPinActive[0] = TRUE;
			
			return true;
			
		}catch (ToolkitException toolkitexception){
			displayConfirmationText(VAR_49);
			return false;
		}
	}

}
