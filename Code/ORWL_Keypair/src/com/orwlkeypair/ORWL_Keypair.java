/**
 * @author chaitra.patil
 * Package AID: 0A 0B 0C 0D 0E 0A
 * Applet AID: 0A 0B 0C 0D 0E 02
 * Applet supports following operations
 * 1. Stores the KeyFOB details during manufacturing mode
 * 2. Retrieval of KeyFOB details anytime
 */
package com.orwlkeypair;

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

	/** Used for storing KeyFOB Name*/
	private byte[] keyfobName;
	private static final short LENGTH_KEYFOB_NAME_BYTES = 254;

	/** Used for storing KeyFOB Serial Number*/
	private byte[] keyfobSerialNum;
	private static final byte LENGTH_KEYFOB_SERIAL_NUM_BYTES = 16;

	/** Used for storing KeyFOB UID*/
	private byte[] keyfobUID;
	private static final byte LENGTH_KEYFOB_UID_BYTES = 16;

	/**
	 * The Constructor registers the applet instance with the JCRE.
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
	 * Checks for the Parameter P1
	 * @param buffer - APDU buffer
	 */
	private void checkForP1Val(byte[] buffer){
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	}

}
