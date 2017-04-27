/**
 * @author chaitra.patil
 * Package AID: 0A 0B 0C 0D 0E 0B
 * Interface defines only BLE seed retrieval
 */
package com.orwlinterface;

import javacard.framework.Shareable;

public interface ORWL_Interface extends Shareable {

	public short retrieveBleSeed(byte[] buffer, short offset);

}
