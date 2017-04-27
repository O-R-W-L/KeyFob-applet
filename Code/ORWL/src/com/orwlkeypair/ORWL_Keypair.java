/**
 * @author chaitra.patil
 * Package AID: 0A 0B 0C 0D 0E 0A
 * Applet AID: 0A 0B 0C 0D 0E 02
 * Applet supports following operations
 * 1. Stores the KeyFOB serial number during manufacturing mode
 * 2. Retrieval of KeyFOB details anytime
 * 3. Retrieve KeyFOB association status
 * 4. ECDH key pair generation and secret key generation
 * 5. Exchange and store the seedX and seedY values
 * 6. CVM pin verification
 * 7. Save the KeyFOB name
 * 8. Save all the encryption/decryption keys and complete the association process
 * 9. Decrypt and save the Ble seed token using ECDH secret key and seedX
 * 10. Authenticate the Ble seed challenge, create message digest and encrypt it using the seedY and ECDH key
 * 11. Implements 3DES Algorithm for data encryption and decryption
 * 12. SHA-1 algorithm is used for message digest creation
 */
package com.orwlkeypair;

import org.globalplatform.CVM;
import org.globalplatform.GPSystem;

import com.orwlinterface.ORWL_Interface;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class ORWL_Keypair extends Applet implements ORWL_Interface{

	/**Supported Class byte by this applet*/
	public final static byte CLA = (byte) 0x90;

	/**Supported INS bytes by this applet*/
	final static byte INS_GET_KEYFOB_SERIAL_NUM = (byte) 0x20;
	final static byte INS_GET_KEYFOB_NAME = (byte) 0x22;

	final static byte INS_STORE_KEYFOB_SERIAL_NUM = (byte) 0x2A;
	final static byte INS_STORE_KEYFOB_NAME = (byte) 0x2C;

	final static byte INS_GET_PUBLIC_KEY = (byte) 0x11;
	final static byte INS_GENERATE_SECRET_KEY = (byte) 0x12;
	final static byte INS_CONFIRM_SECRET_KEY = (byte) 0x10;
	final static byte INS_VERIFY_CVM_PIN = (byte) 0x13;
	final static byte INS_ASSOCIATE_STATUS = (byte) 0x14;
	final static byte INS_SAVE_SEED_KEY = (byte) 0x15;
	final static byte INS_AUTH_SEED_KEY = (byte) 0x16;
	final static byte INS_SAVE_SECRET_KEYS = (byte) 0x17;
	final static byte INS_SAVE_SHARE_SEED_X = (byte) 0x18;
	final static byte INS_GET_SHARE_SEED_Y = (byte) 0x19;

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
     * The keyAssociationFlag can have following values: false => KeyFOB ready for association with any ORWL device(not yet associated)
     * 													 true => already associated with an ORWL device
     */
	private boolean keyAssociationFlag = false;

	private boolean seedXSaveFlag = false;

	/** Used for storing KeyFOB Name*/
	private byte[] keyfobName;
	private static final short LENGTH_KEYFOB_NAME_BYTES = 19;

	/** Used for storing KeyFOB Serial Number*/
	private byte[] keyfobSerialNum;
	private static final byte LENGTH_KEYFOB_SERIAL_NUM_BYTES = 4;

	/** SHA-1 generated encrypted message digest length*/
	private static final short MESSAGE_DIGEST_LENGTH = 24;

	/** Used for storing BLE seed*/
	private byte[] bleSeed;
	private static final short SEED_LENGTH = 40;
	private static final short CHALLENGE_LENGTH = 32;

	/** Used for storing shared seedX and seedY values*/
	private byte[] sharedSeedX;
	private byte[] sharedSeedY;
	private static final short SHARED_SEED_LENGTH = 24;

	/** CVM instance*/
	/*CVM cvm;*/
	private final static byte[] cvmData = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

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

	/** Sample data used for confirming the ECDH secret key generated on both the sides */
	private final static byte[] sampleData = {0x4f, 0x52, 0x57, 0x4c, 0x4b, 0x45, 0x59, 0x46};

	/** Random data generator instance */
	RandomData randomData;

	/** SHA-1 generated message digest instance */
	MessageDigest digestinstance;

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
		bleSeed = new byte[SEED_LENGTH];
		sharedSeedX = new byte[SHARED_SEED_LENGTH];
		sharedSeedY = new byte[SHARED_SEED_LENGTH];

		/** Create CVM interface handle and update the fixed CVM pin and its limit */
		/*cvm = GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN);
		cvm.setTryLimit((byte) 5);
		cvm.update(cvmData, (short)0, (byte) cvmData.length, CVM.FORMAT_BCD);
		cvm.resetState();*/

		/** Create 3-DES cipher and key instance*/
		cipherInstance = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
		sharedSecretKey = new byte[SHARED_SECRET_KEY_LENGTH];

		/** Create random data generator instance and message digest object*/
		randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		digestinstance = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

		/** Generate Public Private Keypair used for ECDH secret key generation*/
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

		/** Applet registration with JCRE*/
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

		/** Check SELECT APDU command*/
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
			/*case INS_VERIFY_CVM_PIN:
				verifyCVM(apdu);
				break;*/
			case INS_ASSOCIATE_STATUS:
				assosiateStatus(apdu);
				break;
			case INS_SAVE_SEED_KEY:
				seedSave(apdu);
				break;
			case INS_AUTH_SEED_KEY:
				seedAuthenticate(apdu);
				break;
			case INS_GET_PUBLIC_KEY:
				getPublickey(apdu);
				break;
			case INS_GENERATE_SECRET_KEY:
				generateSecretKey(apdu);
				break;
			case INS_CONFIRM_SECRET_KEY:
				confirmSecretKey(apdu);
				break;
			case INS_SAVE_SECRET_KEYS:
				saveSecretKeys(apdu);
				break;
			case INS_SAVE_SHARE_SEED_X:
				saveShareSeedX(apdu);
				break;
			case INS_GET_SHARE_SEED_Y:
				retrieveShareSeedY(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * INS 2C - Save KeyFOB Name
	 * Store the KeyFOB Name during authentication process
	 * @param apdu - the incoming APDU consists of KeyFOB Name
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	private void storeKeyFobName(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte keyLength = buffer[ISO7816.OFFSET_P1];
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for KeyFOB Name association, CVM pin verification, block and Paired key association status */
		if (keyLength != (byte)LENGTH_KEYFOB_NAME_BYTES)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		/*else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);*/
		else if(keyAssociationFlag)
			ISOException.throwIt((short) 0x6669);
		else if( nameAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			/** Initializes ECDH secret value and decrypt the data received */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, buffer, (short) 0);

			/** Store the KeyFOB name */
			Util.arrayCopy(buffer, (short) 0, keyfobName, (short)0, LENGTH_KEYFOB_NAME_BYTES);
			nameAssociatedFlag = true;
		}
	}

	/**
	 * INS 22 - Retrieve KeyFOB Name
	 * Retrieve KeyFOB Name if KeyFOB already has a name associated during authentication process
	 * @param apdu - the incoming APDU
	 * @return KeyFOB Name
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
		else if(!keyAssociationFlag)
			ISOException.throwIt((short) 0x6669);
		else if( !nameAssociatedFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			Util.arrayCopy(keyfobName, (short)0, buffer, (short)0, LENGTH_KEYFOB_NAME_BYTES);
			/** Send R-APDU containing KeyFOB Name*/
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
			/** Store the KeyFOB serial number */
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, keyfobSerialNum, (short)0, (short)bytesRecv);
			serialAssociatedFlag = true;
		}
	}

	/**
	 * INS 20 - Retrieve KeyFOB Serial Number
	 * Retrieve KeyFOB Serial Number if KeyFOB already has a Serial Number associated during production mode
	 * @param apdu - the incoming APDU
	 * @return KeyFOB Serial Number
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
			/** Send R-APDU containing KeyFOB Serial Number*/
			apdu.setOutgoingAndSend((short) 0, (short) LENGTH_KEYFOB_SERIAL_NUM_BYTES );
		}
	}

	/**
	 * INS 13 - Verify CVM Pin
	 * Verify the CVM Pin required for every session of keypair
	 * @param apdu - the incoming APDU consists of encrypted CVM pin value
	 * @exception ISOException - with the response bytes per ISO 7816-4
	 */
	/*private void verifyCVM(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		byte pinLength = buffer[ISO7816.OFFSET_P1];
		*//**Check for Proper CVM pin length, CVM pin association status and 3DES initialization status *//*
		if (pinLength != cvmData.length)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(!DESKeyStatus())
			ISOException.throwIt((short) 0x6669);
		else {
			*//** Initializes ECDH secret value and decrypt the data received *//*
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, buffer, (short) 0);
			*//**CVM pin verification *//*
			byte result = (byte)cvm.verify(buffer, (short)0, pinLength, CVM.FORMAT_BCD);
			if(result != (byte)0x00)
				ISOException.throwIt((short) 0x9840);
		}
	}*/

	/**
	 * INS 14 - KeyFOB Association Status
	 * Sends the association status of KeyFOB => 90 00 - Unassociated
	 * 											 69 85 - Associated
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
		else if(keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	}

	/**
	 * INS 15 - Save ble seed
	 * Decrypt and Save the ble seed using ECDH key and seedX as part of association process
     * @param apdu - the incoming APDU consists of encrypted seed of 40 bytes
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void seedSave(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRecv = apdu.setIncomingAndReceive();

		/**Check for Seed length, CVM pin verification, block and Paired key association status */
		if (bytesRecv != (byte)SEED_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		/*else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);*/
		else if( !keyAssociationFlag )
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			/** Initializes ECDH secret value and decrypt the data received */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, buffer, (short) 0);
			/**Set the 3des key to seedX*/
			desKey.setKey(sharedSeedX, (short) 0);
			/** Initializes seedX value and decrypt the data received */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, (short) 0, bytesRecv, bleSeed, (short) 0);
			/**Reset the 3des key to ECDH key*/
			desKey.setKey(sharedSecretKey, (short) 0);
		}
	}

	/**
	 * INS 16 - Authenticate ble seed
	 * Create message digest of the ble challenge and encrypt using seedY and ECDH key as part of association process
     * @param apdu - the incoming APDU
	 * @return Message digest of ble challenge in encrypted form
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void seedAuthenticate(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for CVM pin association, verification, block and Paired key association status */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		/*else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);*/
		else if(!keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else{
			/**Create message digest of BLE challenge*/
			short outputLength = digestinstance.doFinal(bleSeed, (short)0, CHALLENGE_LENGTH, buffer, (short)0);
			Util.arrayCopy(buffer, (short)0x00, buffer, (short)outputLength, (short)(MESSAGE_DIGEST_LENGTH-outputLength));

			/**Set the 3des key to seedY*/
			desKey.setKey(sharedSeedY, (short) 0);
			/** Initializes seedY value and encrypt the data */
			cipherInstance.init(desKey, Cipher.MODE_ENCRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, (short) 0, MESSAGE_DIGEST_LENGTH, buffer, (short) 0);
			/**Reset the 3des key to ECDH key*/
			desKey.setKey(sharedSecretKey, (short) 0);
			/** Initializes ECDH secret value encrypt the data */
			cipherInstance.init(desKey, Cipher.MODE_ENCRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, (short) 0, MESSAGE_DIGEST_LENGTH, buffer, (short) 0);

			/** Send R-APDU containing encrypted message digest of ble challenge*/
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) MESSAGE_DIGEST_LENGTH );
			apdu.sendBytesLong(buffer,(short) 0, (short) MESSAGE_DIGEST_LENGTH );
		}
	}

	/**
	 * Checks for the CVM pin verification status
	 */
	/*private boolean cvmPinVerificationStatus() {
		return cvm.isVerified();
	}*/

	/**
	 * Checks for the CVM pin block status
	 */
	/*private boolean cvmPinBlockStatus() {
		return cvm.isBlocked();
	}*/

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
	 * Retrieve the public key of generated Public - Private Keypair
     * @param apdu - the incoming APDU
	 * @return Public key generated on KeyFOB
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void getPublickey(APDU apdu){
		if(keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		/** Retrieve Public key details*/
		byte[] pubKeyBuffer = JCSystem.makeTransientByteArray((short) PUBLIC_KEY_LENGTH, JCSystem.CLEAR_ON_RESET);
		publicKey.getW(pubKeyBuffer,(short) 0);
		/** Send R-APDU containing public key*/
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) pubKeyBuffer.length);
		apdu.sendBytesLong(pubKeyBuffer,(short) 0,(short) pubKeyBuffer.length);
	}

	/**
	 * INS 12 - Generate ECDH Secret Key
	 * Generate secret key using ECDH algorithm and the public key received and sets the secret key to 3DES algorithm
     * @param apdu - the incoming APDU consists of the public key
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void generateSecretKey(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		if(keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
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

	/**
	 * INS 10 - Confirm ECDH Secret Key
	 * Confirm the ECDH generated secret key
     * @param apdu - the incoming APDU consists of sample data encrypted with ECDH key
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void confirmSecretKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRecv = apdu.setIncomingAndReceive();

		/**Check for KeyFOB association status and ECDH key status*/
		if (bytesRecv != (byte)sampleData.length)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else if(!DESKeyStatus())
			ISOException.throwIt((short) 0x6669);
		else{
			/** Initializes ECDH secret value and decrypt the data */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, buffer, (short) 0);
			/** Compare the decrypted data with the sample data */
			byte result = Util.arrayCompare(sampleData, (short)0, buffer, (short)0, bytesRecv);
			if(result != 0)
				ISOException.throwIt((short) 0x9405);
		}
	}

	/**
	 * INS 17 - Save all secret Keys
	 * Save ECDH Secret Key and seed values
     * @param apdu - the incoming APDU
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void saveSecretKeys(APDU apdu) {
		short bytesRecv = apdu.setIncomingAndReceive();

		/**Check for Generation and exchange of secret keys, CVM pin verification, block and KeyFOB association status */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		/*else if(cvmPinBlockStatus() )
			ISOException.throwIt((short) 0x9D61);
		else if(!cvmPinVerificationStatus())
			ISOException.throwIt((short) 0x9840);*/
		else if(!DESKeyStatus() || !seedXSaveFlag)
			ISOException.throwIt((short) 0x6669);
		else
			keyAssociationFlag = true;
	}

	/**
	 * INS 18 - Save seedX
	 * Save the shared seedX
     * @param apdu - the incoming APDU consists of shared seedX
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void saveShareSeedX(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRecv = apdu.setIncomingAndReceive();
		byte keyLength = buffer[ISO7816.OFFSET_P1];

		/**Check for generation of ECDH key and KeyFOB association status */
		if (keyLength != (byte)SHARED_SEED_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(keyAssociationFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else if(!DESKeyStatus())
			ISOException.throwIt((short) 0x6669);
		else{
			/** Initializes ECDH secret value and decrypt the data */
			cipherInstance.init(desKey, Cipher.MODE_DECRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRecv, sharedSeedX, (short) 0);
			seedXSaveFlag = true;
		}
	}

	/**
	 * INS 19 - Generate and Save seedY
	 * Generate and Save the shared seedY
     * @param apdu - the incoming APDU
     * @return SeedY value
     * @exception ISOException - with the response bytes per ISO 7816-4
     */
	private void retrieveShareSeedY(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte bytesRecv = (byte) apdu.setIncomingAndReceive();
		/**Check for P1 Parameter value */
		checkForP1Val(buffer);

		/**Check for generation of ECDH key and KeyFOB association status */
		if (bytesRecv != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else if(keyAssociationFlag || !seedXSaveFlag)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		else if(!DESKeyStatus())
			ISOException.throwIt((short) 0x6669);
		else{
			/**Generate random value of 24 bytes */
			randomData.generateData(sharedSeedY, (short)0x00, SHARED_SEED_LENGTH);

			/** Initializes ECDH secret value and encrypt the data */
			cipherInstance.init(desKey, Cipher.MODE_ENCRYPT, IVVal, (short) 0, (short) IVVal.length);
			cipherInstance.doFinal(sharedSeedY, (short) 0, SHARED_SEED_LENGTH, buffer, (short) 0);
			/** Send R-APDU consists of seedY value*/
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) SHARED_SEED_LENGTH );
			apdu.sendBytesLong(buffer,(short) 0, (short) SHARED_SEED_LENGTH );
		}
	}

	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		return (Shareable) this;
	}

	public short retrieveBleSeed(byte[] buffer, short offset) {
		Util.arrayCopy(bleSeed, (short) 0, buffer, offset, (short) bleSeed.length);
		byte[] temp = JCSystem.makeTransientByteArray((short) bleSeed.length, JCSystem.CLEAR_ON_RESET);
		Util.arrayCopy(temp, (short) 0, bleSeed, offset, (short) bleSeed.length);
		return (short) bleSeed.length;
	}
}