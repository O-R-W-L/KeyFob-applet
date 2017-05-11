/**
 * @author chaitra.patil
 * Package AID: A0 00 00 07 38 0B
 * Applet AID: A0 00 00 07 38 02
 * Applet supports following operation
 * 1. Retrieval of BLE seed stored during authentication process in ORWL_Keypair applet
 */
package com.orwlbleseed;

import com.orwlinterface.ORWL_Interface;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class ORWL_BLESeed extends Applet {

	/**Supported Class byte by this applet*/
	public final static byte CLA = (byte) 0x90;

	/**Supported INS bytes by this applet*/
	final static byte INS_GET_BLE_SEED = (byte) 0x40;

	/** AID instance*/
	AID keyPairAppletAID;
	private ORWL_Interface orwlInterfaceInst;
	/** ORWL_Keypair AID*/
	byte[] aidBuffer = {(byte) 0xA0, 0x00, 0x00, 0x07, 0x38, 0x01};

	/**
	 * The Constructor registers the applet instance with the JCRE.
	 * The applet instance is created in the install() method.
	 * @param bArray the array containing installation parameters.
	 * @param bOffset the starting offset in bArray.
	 * @param bLength the length in bytes of the parameter data in bArray.
	 * The maximum value of length is 32.
	 */
	public ORWL_BLESeed(byte[] bArray, short bOffset, byte bLength) {
		/** ORWL_Keypair applet AID object*/
		keyPairAppletAID = JCSystem.lookupAID(aidBuffer, (short) 0, (byte) aidBuffer.length);
		/** The first byte of bArray is the length of the instance AID bytes*/
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
		new ORWL_BLESeed(bArray, bOffset, bLength);
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
		else if (buffer[ISO7816.OFFSET_P2] != 0 || buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		/**Associate particular command to particular method*/
		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_GET_BLE_SEED:
				/**ORWL_Keypair applet shareable interface object*/
				orwlInterfaceInst = (ORWL_Interface) JCSystem.getAppletShareableInterfaceObject(keyPairAppletAID, (byte) 0);
				/**Retrieval of BLE seed value from ORWL_Keypair applet and send as response*/
				short outputLen = orwlInterfaceInst.retrieveBleSeed(buffer, (short)0);
				apdu.setOutgoingAndSend((short)0, outputLen);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

}
