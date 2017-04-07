/**
 * @author chaitra.patil
 * Package AID: 0A 0B 0C 0D 0E 0A
 * Applet AID: 0A 0B 0C 0D 0E 02
 * Applet supports following operations
 * 1. Stores the KeyFOB details during manufacturing mode
 * 2. Retrieval of KeyFOB details anytime
 * 3. Save or Update CVM pin during manufacturing mode and in every session after CVM pin verification
 * 4. CVM pin verification
 * 5. Retrieve KeyFOB association status
 * 6. Store the pairing key for association of KeyFOB with an ORWL device  after CVM pin verification
 * 7. Read the paired key after CVM pin verification
 */
package com.orwlkeypair;

import org.globalplatform.CVM;
import org.globalplatform.GPSystem;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class ORWL_Keypair extends Applet {

	/**Supported Class byte by this applet*/
	public final static byte CLA = (byte) 0x90;

	/**Supported INS bytes by this applet*/
	final static byte INS_GET_KEYFOB_SERIAL_NUM = (byte) 0x20;
	final static byte INS_GET_KEYFOB_UID = (byte) 0x21;
	final static byte INS_GET_KEYFOB_NAME = (byte) 0x22;

	final static byte INS_STORE_KEYFOB_SERIAL_NUM = (byte) 0x2A;
	final static byte INS_STORE_KEYFOB_UID = (byte) 0x2B;
	final static byte INS_STORE_KEYFOB_NAME = (byte) 0x2C;
	final static byte INS_STORE_CVM_PIN = (byte) 0x2D;

	final static byte INS_VERIFY_CVM_PIN = (byte) 0x13;
	final static byte INS_ASSOCIATE_STATUS = (byte) 0x14;
	final static byte INS_STORE_KEY = (byte) 0x15;
	final static byte INS_READ_KEY = (byte) 0x16;

	/**
     * The nameAssociatedFlag can have following values: false => Ready for KeyFOB Name association(not yet associated)
     * 													 true => KeyFOB name already associated
     */
	private boolean nameAssociatedFlag = false;

	/**
     * The serialAssociatedFlag can have following values: false => Ready for KeyFOB Serial Number association(not yet associated)
     * 													   true => KeyFOB serial number already associated
     */
	private boolean serialAssociatedFlag = false;

	/**
     * The uidAssociatedFlag can have following values: false => Ready for KeyFOB UID association(not yet associated)
     * 													true => KeyFOB UID already associated
     */
	private boolean uidAssociatedFlag = false;

	/**
     * The cvmAssociatedFlag can have following values: false => Ready for CVM Pin first time store
     * 													true => CVM Pin cannot be stored
     */
	private boolean cvmAssociatedFlag = false;

	/**
     * The keyAssociationFlag can have following values: false => KeyFOB ready for association with any ORWL device(not yet associated)
     * 													true => already associated with an ORWL device
     */
	private boolean keyAssociationFlag = false;

	/** Used for storing KeyFOB Name*/
	private byte[] keyfobName;
	private static final short LENGTH_KEYFOB_NAME_BYTES = 254;

	/** Used for storing KeyFOB Serial Number*/
	private byte[] keyfobSerialNum;
	private static final byte LENGTH_KEYFOB_SERIAL_NUM_BYTES = 16;

	/** Used for storing KeyFOB UID*/
	private byte[] keyfobUID;
	private static final byte LENGTH_KEYFOB_UID_BYTES = 16;

	/** Used for storing 128-bytes Unique key which is used for pairing KeyFOB with ORWL device*/
	private byte[] pairKey;
	private static final short PAIR_KEY_LENGTH = 128;

	/** CVM pin length*/
	private static final byte CVM_PIN_LENGTH = 6;

	/** CVM instance*/
	CVM cvm;

	/**The Constructor registers the applet instance with the JCRE.
	 * The applet instance is created in the install() method.
	 * @param bArray the array containing installation parameters.
	 * @param bOffset the starting offset in bArray.
	 * @param bLength the length in bytes of the parameter data in bArray.
	 * The maximum value of length is 32.
	 */
	public ORWL_Keypair(byte[] bArray, short bOffset, byte bLength) {
		/** Initialize the KeyFOB buffers*/
		keyfobName = new byte[LENGTH_KEYFOB_NAME_BYTES];
		keyfobSerialNum = new byte[LENGTH_KEYFOB_SERIAL_NUM_BYTES];
		keyfobUID = new byte[LENGTH_KEYFOB_UID_BYTES];

		pairKey = new byte[PAIR_KEY_LENGTH];
		cvm = GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN);

		register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	/**
	 * The Java Card Runtime Environment will call this static method first.
	 * The installation is considered successful when the call <br>
	 * to <code>register()</code> completes without an exception.
	 * @param bArray the array containing installation parameters.
	 * @param bOffset the starting offset in bArray.
	 * @param bLength the length in bytes of the parameter data in bArray.
	 * @throws ISOException if the install method failed.
	 * @see javacard.framework.Applet#install(byte[], short, byte)
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ORWL_Keypair(bArray, bOffset, bLength);
	}

	/**
	 * Processes an incoming APDU
	 */
	public void process(APDU apdu) throws ISOException {
		byte buffer[] = apdu.getBuffer();

		/** check SELECT APDU command*/
		if (selectingApplet())
			return;
		else if(buffer[ISO7816.OFFSET_CLA] != CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		else if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

		/**Associate particular command to particular method*/
		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_STORE_KEYFOB_NAME:
				storeKeyFobName(apdu);
				break;
			case INS_GET_KEYFOB_NAME:
				getKeyFobName(apdu);
				break;
			case INS_STORE_KEYFOB_SERIAL_NUM:
				storeKeyFobSerial(apdu);
				break;
			case INS_GET_KEYFOB_SERIAL_NUM:
				getKeyFobSerial(apdu);
				break;
			case INS_STORE_KEYFOB_UID:
				storeKeyFobUID(apdu);
				break;
			case INS_GET_KEYFOB_UID:
				getKeyFobUID(apdu);
				break;
			case INS_STORE_CVM_PIN:
				parseAndUpdateCVMPin(apdu);
				break;
			case INS_VERIFY_CVM_PIN:
				verifyCVM(apdu);
				break;
			case INS_ASSOCIATE_STATUS:
				assosiateStatus(apdu);
				break;
			case INS_STORE_KEY:
				storePairingKey(apdu);
				break;
			case INS_READ_KEY:
				getPairedKey(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * INS 2C - Save KeyFOB Name
	 * Store the KeyFOB Name for the first time during production mode
	 * @param apdu - the incoming APDU consists of KeyFOB Name
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void storeKeyFobName(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		/**Check for KeyFOB Name association */
		if( nameAssociatedFlag == true)
			buffer[0] = (byte)0x0E;
		else{
			byte bytesRecv = (byte) apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, keyfobName, (short)0, (short)bytesRecv);
			nameAssociatedFlag = true;
			buffer[0] = (byte)0x01;
		}
		/** Send R-APDU*/
		apdu.setOutgoingAndSend((short) 0, (byte)0x01);
	}

	/**
	 * INS 22 - Retrieve KeyFOB Name
	 * Retrieve KeyFOB Name if KeyFOB already has a name associated during production mode
	 * @param apdu - the incoming APDU
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void getKeyFobName(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for Proper length and KeyFOB Name association */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if( nameAssociatedFlag == false){
			buffer[0] = (byte)0x0E;
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (byte)0x01);
		}
		else{
			buffer[0] = (byte)0x01;
			buffer[1] = (byte) LENGTH_KEYFOB_NAME_BYTES;
			Util.arrayCopy(keyfobName, (short)0, buffer, (short)0x02, LENGTH_KEYFOB_NAME_BYTES);
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (short) (LENGTH_KEYFOB_NAME_BYTES + (byte)0x02));
		}
	}

	/**
	 * INS 2A - Save KeyFOB Serial Number
	 * Store the KeyFOB Serial Number for the first time during production mode
	 * @param apdu - the incoming APDU consists of KeyFOB Serial Number
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void storeKeyFobSerial(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		/**Check for KeyFOB Serial Number association */
		if( serialAssociatedFlag == true)
			buffer[0] = (byte)0x0E;
		else{
			byte bytesRecv = (byte) apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, keyfobSerialNum, (short)0, (short)bytesRecv);
			serialAssociatedFlag = true;
			buffer[0] = (byte)0x01;
		}
		/** Send R-APDU*/
		apdu.setOutgoingAndSend((short) 0, (byte)0x01);
	}

	/**
	 * INS 20 - Retrieve KeyFOB Serial Number
	 * Retrieve KeyFOB Serial Number if KeyFOB already has a Serial Number associated during production mode
	 * @param apdu - the incoming APDU
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void getKeyFobSerial(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for Proper length and KeyFOB Serial Number association */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if( serialAssociatedFlag == false){
			buffer[0] = (byte)0x0E;
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (byte)0x01);
		}
		else{
			buffer[0] = (byte)0x01;
			buffer[1] = (byte) LENGTH_KEYFOB_SERIAL_NUM_BYTES;
			Util.arrayCopy(keyfobSerialNum, (short)0, buffer, (short)0x02, LENGTH_KEYFOB_SERIAL_NUM_BYTES);
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (short) (LENGTH_KEYFOB_SERIAL_NUM_BYTES + (byte)0x02));
		}
	}

	/**
	 * INS 2B - Save KeyFOB UID
	 * Store the KeyFOB UID for the first time during production mode
	 * @param apdu - the incoming APDU
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void storeKeyFobUID(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		/**Check for KeyFOB UID association */
		if( uidAssociatedFlag == true)
			buffer[0] = (byte)0x0E;
		else{
			byte bytesRecv = (byte) apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, keyfobUID, (short)0, (short)bytesRecv);
			uidAssociatedFlag = true;
			buffer[0] = (byte)0x01;
		}
		/** Send R-APDU*/
		apdu.setOutgoingAndSend((short) 0, (byte)0x01);
	}

	/**
	 * INS 21 - Retrieve KeyFOB UID
	 * Retrieve KeyFOB UID if KeyFOB already has a UID associated during production mode
	 * @param apdu - the incoming APDU
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void getKeyFobUID(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for Proper length and KeyFOB UID association */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if( uidAssociatedFlag == false){
			buffer[0] = (byte)0x0E;
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (byte)0x01);
		}
		else{
			buffer[0] = (byte)0x01;
			buffer[1] = (byte) LENGTH_KEYFOB_UID_BYTES;
			Util.arrayCopy(keyfobUID, (short)0, buffer, (short)0x02, LENGTH_KEYFOB_UID_BYTES);
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (short) (LENGTH_KEYFOB_UID_BYTES + (byte)0x02));
		}
	}

	/**
	 * INS 2D - Save CVM Pin
	 * Store/Update the CVM Pin for the first time during production mode and after successful pin verification during every session of communication
	 * @param apdu - the incoming APDU consists of CVM pin
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void parseAndUpdateCVMPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for CVM Pin verification */
		boolean cvmVerifyFlag = cvmPinVerificationStatus();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		/**Check for Proper CVM pin length and CVM pin association */
		if (bytesRecv != CVM_PIN_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(cvmAssociatedFlag == false || (cvmVerifyFlag == true && cvmAssociatedFlag == true)){
			/**CVM pin update */
			cvm.resetAndUnblockState();
			cvm.update(buffer, ISO7816.OFFSET_CDATA, bytesRecv, CVM.FORMAT_BCD);
			cvm.resetState();
			/**CVM pin verification */
			cvm.verify(buffer, ISO7816.OFFSET_CDATA, bytesRecv, CVM.FORMAT_BCD);
			/**Retrieve CVM pin retry limit remaining */
			buffer[0] = cvm.getTriesRemaining();
			cvmAssociatedFlag = true;
		}
		else
			buffer[0] = (byte)0x0E;
		/** Send R-APDU*/
		apdu.setOutgoingAndSend((short) 0, (byte)0x01);
	}

	/**
	 * INS 13 - Verify CVM Pin
	 * Verify the CVM Pin required for every session of keypair
	 * @param apdu - the incoming APDU consists of CVM pin
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void verifyCVM(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		/**Check for Proper CVM pin length and CVM pin association status */
		if (bytesRecv != CVM_PIN_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if( cvmAssociatedFlag == false )
			buffer[0] = (byte)0x1E;
		else {
			/**CVM pin verification */
			byte result = (byte)cvm.verify(buffer, ISO7816.OFFSET_CDATA, bytesRecv, CVM.FORMAT_BCD);
			if(result != (byte)0x00)
				buffer[0] = (byte)0x0E;
			else
				buffer[0] = (byte)0x01;
		}
		/** Send R-APDU*/
		apdu.setOutgoingAndSend((short) 0, (byte)0x01);

	}

	/**
	 * INS 14 - KeyFOB Association Status
	 * Sends the association status of KeyFOB => Accept(0x01) indicating Unassociated and reject(0x0E)indicating Associated Status
     * @param apdu - the incoming APDU
     * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void assosiateStatus(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Retrieve CVM Verification and block status */
		boolean cvmVerifyFlag = cvmPinVerificationStatus();
		boolean cvmBlockFlag = cvmPinBlockStatus();
		/**Check for CVM pin verification, block and association status */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(cvmBlockFlag == true )
			buffer[0] = (byte)0x2E;
		else if( cvmVerifyFlag == false || cvmAssociatedFlag == false)
			buffer[0] = (byte)0x1E;
		else if( keyAssociationFlag == true )
			buffer[0] = (byte)0x0E;
		else
			buffer[0] = (byte)0x01;
		/** Send R-APDU*/
		apdu.setOutgoingAndSend((short) 0, (byte)0x01);
	}


	/**
	 * INS 15 - Save Pairing Key
	 * Store the key on the card as part of association process
     * @param apdu - the incoming APDU consists of key of 128 bytes
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void storePairingKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRecv = apdu.setIncomingAndReceive();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		/**Retrieve CVM Verification and block status */
		boolean cvmVerifyFlag = cvmPinVerificationStatus();
		boolean cvmBlockFlag = cvmPinBlockStatus();
		/**Check for Pair key length, CVM pin verification, block and Paired key association status */
		if (bytesRecv != PAIR_KEY_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(cvmBlockFlag == true )
			buffer[0] = (byte)0x2E;
		else if( cvmVerifyFlag == false || cvmAssociatedFlag == false)
			buffer[0] = (byte)0x1E;
		else if( keyAssociationFlag == true )
			buffer[0] = (byte)0x0E;
		else{
			/**Save pairing key */
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pairKey, (short)0, (short)PAIR_KEY_LENGTH);
			keyAssociationFlag = true;
			buffer[0] = (byte)0x01;
		}
		/** Send R-APDU*/
        apdu.setOutgoingAndSend((short) 0, (byte)0x01);
	}


	/**
	 * INS 16 - Read Paired Key
	 * Retrieve associated key if pairing had already happened
     * @param apdu - the incoming APDU
	 * @return Paired key
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void getPairedKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Retrieve CVM Verification and block status */
		boolean cvmVerifyFlag = cvmPinVerificationStatus();
		boolean cvmBlockFlag = cvmPinBlockStatus();
		/**Check for CVM pin verification, block and Paired key association status */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(cvmBlockFlag == true )
			buffer[0] = (byte)0x2E;
		else if( cvmVerifyFlag == false || cvmAssociatedFlag == false)
			buffer[0] = (byte)0x1E;
		else if( keyAssociationFlag == false )
			 buffer[0] = (byte)0x0E;
		else{
			buffer[0] = (byte)0x01;
			/**Retrieve pairing key */
			Util.arrayCopy(pairKey, (short)0, buffer, (short)0x01, PAIR_KEY_LENGTH);
			/** Send R-APDU*/
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) (PAIR_KEY_LENGTH + 1));
			apdu.sendBytesLong(buffer,(short) 0, (short) (PAIR_KEY_LENGTH + 1));
			return;
		}
		/** Send R-APDU*/
		apdu.setOutgoingAndSend((short) 0, (byte)0x01);
	}

	/**
	 * Checks for the CVM pin verification status
	 */
	private boolean cvmPinVerificationStatus() {
		return cvm.isVerified();
	}

	/**
	 * Checks for the CVM pin block status
	 */
	private boolean cvmPinBlockStatus() {
		return cvm.isBlocked();
	}

	/**
	 * Checks for the Parameter P1
	 * @param buffer - APDU buffer
	 */
	private void checkForP1Val(byte[] buffer){
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	}

}
