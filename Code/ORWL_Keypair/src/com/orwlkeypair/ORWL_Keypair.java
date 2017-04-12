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
 * 8. Implements 3DES Algorithm for data encryption and decryption
 */
package com.orwlkeypair;

import org.globalplatform.CVM;
import org.globalplatform.GPSystem;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;

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

	final static byte INS_GET_PUBLIC_KEY = (byte) 0x11;
	final static byte INS_GENERATE_SECRET_KEY = (byte) 0x12;
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
	private static final short LENGTH_KEYFOB_NAME_BYTES = 255;

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

	/** Cipher instance*/
	private Cipher cipherInstance;

	/** 3DES key instance*/
	private DESKey desKey;

	/** 3DES common Initialization vector value */
	private byte[] IVVal = {0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78};

	/** 192-bit r1 elliptic curve domain parameters */
	private final static byte[] primeP = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	private final static byte[] coefficientA = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc};

	private final static byte[] coefficientB = { 0x64, 0x21, 0x05, 0x19, (byte) 0xe5, (byte) 0x9c, (byte) 0x80, (byte) 0xe7, 0x0f, (byte) 0xa7,
		(byte) 0xe9, (byte) 0xab, 0x72, 0x24, 0x30, 0x49, (byte) 0xfe, (byte) 0xb8, (byte) 0xde, (byte) 0xec, (byte) 0xc1, 0x46, (byte) 0xb9,
		(byte) 0xb1 };

	private final static byte[] fixedPointG = { 0x04, 0x18, (byte) 0x8d, (byte) 0xa8, 0x0e, (byte) 0xb0, 0x30, (byte) 0x90, (byte) 0xf6, 0x7c,
		(byte) 0xbf, 0x20, (byte) 0xeb, 0x43, (byte) 0xa1, (byte) 0x88, 0x00, (byte) 0xf4, (byte) 0xff, 0x0a, (byte) 0xfd, (byte) 0x82, (byte) 0xff,
		0x10, 0x12, 0x7, 0x19, 0x2b, (byte) 0x95, (byte) 0xff, (byte) 0xc8, (byte) 0xda, 0x78, 0x63, 0x10, 0x11, (byte) 0xed, 0x6b, 0x24, (byte) 0xcd,
		(byte) 0xd5, 0x73, (byte) 0xf9, 0x77, (byte) 0xa1, 0x1e, 0x79, 0x48, 0x11 };

	private final static byte[] orderR = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x99, (byte) 0xde, (byte) 0xf8, 0x36, 0x14, 0x6b, (byte) 0xc9, (byte) 0xb1,
		(byte) 0xb4, (byte) 0xd2, 0x28, 0x31 };

	/** Elliptic curve public and private key instance */
	ECPrivateKey privateKey;
	ECPublicKey publicKey;
	private static final short PUBLIC_KEY_LENGTH = 49;
	/** ECDH instance */
	KeyAgreement ecdhInstance;

	/** 3DES shared secret key */
	private byte[] sharedSecretKey;
	private static final short SHARED_SECRET_KEY_LENGTH = 24;

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

		/** Initialize 3-DES cipher instance*/
		cipherInstance = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
		sharedSecretKey = new byte[SHARED_SECRET_KEY_LENGTH];

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
			case INS_GET_PUBLIC_KEY:
				getPublickey(apdu);
				break;
			case INS_GENERATE_SECRET_KEY:
				generateSecretKey(apdu);
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
		if( nameAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			byte bytesRecv = (byte) apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, keyfobName, (short)0, (short)bytesRecv);
			nameAssociatedFlag = true;
		}
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
		else if( !nameAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			Util.arrayCopy(keyfobName, (short)0, buffer, (short)0, LENGTH_KEYFOB_NAME_BYTES);
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (short) LENGTH_KEYFOB_NAME_BYTES);
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
		if( serialAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			byte bytesRecv = (byte) apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, keyfobSerialNum, (short)0, (short)bytesRecv);
			serialAssociatedFlag = true;
		}
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
		else if( !serialAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			Util.arrayCopy(keyfobSerialNum, (short)0, buffer, (short)0, LENGTH_KEYFOB_SERIAL_NUM_BYTES);
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (short) LENGTH_KEYFOB_SERIAL_NUM_BYTES );
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
		if( uidAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			byte bytesRecv = (byte) apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, keyfobUID, (short)0, (short)bytesRecv);
			uidAssociatedFlag = true;
		}
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
		else if( !uidAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			Util.arrayCopy(keyfobUID, (short)0, buffer, (short)0, LENGTH_KEYFOB_UID_BYTES);
			/** Send R-APDU*/
			apdu.setOutgoingAndSend((short) 0, (short) LENGTH_KEYFOB_UID_BYTES );
		}
	}

	/**
	 * INS 2D - Save CVM Pin
	 * Store/Update the CVM Pin for the first time during production mode and after successful pin verification during every session of communication
	 * @param apdu - the incoming APDU consists of CVM pin(Encrypted form during every session communication and plain command during manufacture mode)
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void parseAndUpdateCVMPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		byte pinLength = buffer[ISO7816.OFFSET_P1];
		/**Check for Proper CVM pin length and CVM pin association and verification */
		if (pinLength != CVM_PIN_LENGTH || (!cvmAssociatedFlag && bytesRecv != CVM_PIN_LENGTH))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if( !cvmAssociatedFlag )
			updateCVMPin(apdu, buffer, pinLength, ISO7816.OFFSET_CDATA);
		else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);
		else {
			cvm.resetAndUnblockState();
			cvm.update(buffer, ISO7816.OFFSET_CDATA, bytesRecv, CVM.FORMAT_BCD);
			cvm.resetState();
			/**CVM pin verification */
			cvm.verify(buffer, ISO7816.OFFSET_CDATA, bytesRecv, CVM.FORMAT_BCD);
			/**Retrieve CVM pin retry limit remaining */
			buffer[0] = cvm.getTriesRemaining();
			cvmAssociatedFlag = true;
			/**Create temp buffer to hold the decrypted data */
			byte[] temp = JCSystem.makeTransientByteArray(bytesRecv, JCSystem.CLEAR_ON_RESET);
			/**Set initialize secret values and decrypt the data received */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, temp, (short) 0);
			/**Copy temp buffer decrypted data to APDU buffer for CVM pin update and verification */
			Util.arrayCopy(temp, (short)0, buffer, (short)0, pinLength);
			updateCVMPin(apdu, buffer, pinLength, (short) 0);
		}
	}

	/**
	 * Updates and verifies the CVM pin
	 * @param buffer - holds the CVM pin value(decrypted during every session communication and plain during manufacture mode)
	 */
	private void updateCVMPin(APDU apdu, byte[] buffer, byte pinLength, short offset) {
		/**CVM Pin update */
		cvm.update(buffer, offset, pinLength, CVM.FORMAT_BCD);
		cvm.resetState();
		/**CVM Pin verification */
		cvm.verify(buffer, offset, pinLength, CVM.FORMAT_BCD);
		cvmAssociatedFlag = true;
	}

	/**
	 * INS 13 - Verify CVM Pin
	 * Verify the CVM Pin required for every session of keypair
	 * @param apdu - the incoming APDU consists of encrypted CVM pin value
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void verifyCVM(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		byte pinLength = buffer[ISO7816.OFFSET_P1];
		/**Check for Proper CVM pin length, CVM pin association status and 3DES initialization status */
		if (pinLength != CVM_PIN_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if( !cvmAssociatedFlag )
			ISOException.throwIt((short) 0x9802);
		else if(!DESKeyStatus())
			ISOException.throwIt((short) 0x6669);
		else {
			byte[] temp = JCSystem.makeTransientByteArray(bytesRecv, JCSystem.CLEAR_ON_RESET);
			/**Set initialize secret values and decrypt the data received */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, temp, (short) 0);
			/**Copy temp buffer decrypted data to APDU buffer for CVM pin verification */
			Util.arrayCopy(temp, (short)0, buffer, (short)0, pinLength);
			/**CVM pin verification */
			byte result = (byte)cvm.verify(buffer, (short)0, pinLength, CVM.FORMAT_BCD);
			if(result != (byte)0x00)
				ISOException.throwIt((short) 0x9840);
		}
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
		/**Check for CVM pin verification, block and association status */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmAssociatedFlag)
			ISOException.throwIt((short) 0x9802);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);
		else if(keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	}

	/**
	 * INS 15 - Save Pairing Key
	 * Store the key on the card as part of association process
     * @param apdu - the incoming APDU consists of encrypted key of 128 bytes
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void storePairingKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRecv = apdu.setIncomingAndReceive();
		byte keyLength = buffer[ISO7816.OFFSET_P1];

		/**Check for Pair key length, CVM pin verification, block and Paired key association status */
		if (keyLength != (byte)PAIR_KEY_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmAssociatedFlag)
			ISOException.throwIt((short) 0x9802);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);
		else if( keyAssociationFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			/**Save pairing key */
			byte[] temp = JCSystem.makeTransientByteArray(PAIR_KEY_LENGTH, JCSystem.CLEAR_ON_RESET);
			/**Set initialize secret values and decrypt the data received */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, temp, (short) 0);

			/**Copy temp buffer decrypted data to paiKey buffer */
			Util.arrayCopy(temp, (short)0, pairKey, (short)0, (short)PAIR_KEY_LENGTH);
			keyAssociationFlag = true;
		}
	}


	/**
	 * INS 16 - Read Paired Key
	 * Retrieve associated key if pairing had already happened
     * @param apdu - the incoming APDU
	 * @return Paired key in encrypted form
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void getPairedKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for CVM pin association, verification, block and Paired key association status */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmAssociatedFlag)
			ISOException.throwIt((short) 0x9802);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);
		else if(!keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			/**Retrieve pairing key */
			byte[] temp = JCSystem.makeTransientByteArray(PAIR_KEY_LENGTH, JCSystem.CLEAR_ON_RESET);
			/**Copy paiKey buffer data to temp buffer for encryption*/
			Util.arrayCopy(pairKey, (short)0, temp, (short)0x00, PAIR_KEY_LENGTH);
			/**Set initialize secret values and encrypt the data to be sent */
			cipherInstance.init(desKey, Cipher.MODE_ENCRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(temp, (short) 0, PAIR_KEY_LENGTH, buffer, (short) 0);
			/** Send R-APDU*/
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) PAIR_KEY_LENGTH );
			apdu.sendBytesLong(buffer,(short) 0, (short) PAIR_KEY_LENGTH );
		}
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

	/**
	 * INS 11 - Get Public Key
	 * Generate Public - Private Keypair and retrieve the public key
     * @param apdu - the incoming APDU
	 * @return Public key generated on KeyFOB
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void getPublickey(APDU apdu){
		/** Generate Public Private Keypair*/
		KeyPair key = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);

		privateKey = (ECPrivateKey) key.getPrivate();
		publicKey = (ECPublicKey) key.getPublic();

		/** Set domain parameters to public and private keys*/
		privateKey.setFieldFP(primeP, (short) 0, (short) primeP.length);
		privateKey.setA(coefficientA, (short) 0, (short) coefficientA.length);
		privateKey.setB(coefficientB, (short) 0, (short) coefficientB.length);
		privateKey.setG(fixedPointG, (short) 0, (short) fixedPointG.length);
		privateKey.setR(orderR, (short) 0, (short) orderR.length);

		publicKey.setFieldFP(primeP, (short) 0, (short) primeP.length);
		publicKey.setA(coefficientA, (short) 0, (short) coefficientA.length);
		publicKey.setB(coefficientB, (short) 0, (short) coefficientB.length);
		publicKey.setG(fixedPointG, (short) 0, (short) fixedPointG.length);
		publicKey.setR(orderR, (short) 0, (short) orderR.length);

		key.genKeyPair();
		/** Retrieve Public key details*/
		byte[] pubKeyBuffer = JCSystem.makeTransientByteArray((short) PUBLIC_KEY_LENGTH, JCSystem.CLEAR_ON_RESET);
		publicKey.getW(pubKeyBuffer,(short) 0);
		/** Send R-APDU containing public key*/
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) pubKeyBuffer.length);
		apdu.sendBytesLong(pubKeyBuffer,(short) 0,(short) pubKeyBuffer.length);
	}

	/**
	 * INS 12 - Generate Secret Key
	 * Generate secret key using ECDH algorithm and the public key received and sets the secret key to 3DES algorithm
     * @param apdu - the incoming APDU consists of the public key
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void generateSecretKey(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/** Retrieve the Public key data sent by ORWL*/
		byte[] pubKeyBuffer = JCSystem.makeTransientByteArray(bytesRecv, JCSystem.CLEAR_ON_RESET);
		Util.arrayCopyNonAtomic(buffer,ISO7816.OFFSET_CDATA, pubKeyBuffer, (short)0, bytesRecv);
		/** Generate shared secret key using ECDH algorithm*/
		ecdhInstance = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		ecdhInstance.init(privateKey);
		short secretLen = ecdhInstance.generateSecret(pubKeyBuffer, (short)0, bytesRecv, sharedSecretKey, (short)0);
		/** Save shared secret key generated*/
		Util.arrayCopyNonAtomic(sharedSecretKey,(short)0, sharedSecretKey, (short)secretLen, (short) (SHARED_SECRET_KEY_LENGTH - secretLen));
		/** Set 3DES shared secret key*/
		desKey.setKey(sharedSecretKey, (short) 0);
	}

	/**
	 * Checks for 3DES initialization status
	 */
	private boolean DESKeyStatus() {
		return desKey.isInitialized();
	}

}
