/**
 * @author chaitra.patil
 * Package AID: A0 00 00 07 38 0C
 * Interface defines only BLE seed retrieval
 */
package com.orwlinterface;

import javacard.framework.Shareable;

public interface ORWL_Interface extends Shareable {

	public short retrieveBleSeed(byte[] buffer, short offset);

}
