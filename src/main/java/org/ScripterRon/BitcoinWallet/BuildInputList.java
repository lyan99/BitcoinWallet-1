/**
 * Copyright 2013-2017 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinWallet;

import org.ScripterRon.BitcoinCore.ECKey;
import org.ScripterRon.BitcoinCore.OutPoint;
import org.ScripterRon.BitcoinCore.Script;
import org.ScripterRon.BitcoinCore.ScriptOpCodes;
import org.ScripterRon.BitcoinCore.SignedInput;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Build the input list for a new transaction
 */
public class BuildInputList {

    /**
     * Build the signed input list for creating a new transaction.  The list will not
     * include pending transactions, spent transactions or transactions in the safe.
     * A coinbase transaction must be mature before it can be spent.
     *
     * @param       coinControl         TRUE to use coin control
     * @return                          Signed input list
     * @throws      WalletException     Unable to get list of unspent outputs
     */
    public static List<SignedInput> buildSignedInputs(boolean coinControl) throws WalletException {
        List<SignedInput> inputList = new LinkedList<>();
        //
        // Get the list of available transaction outputs
        //
        List<ReceiveTransaction> txList = Parameters.wallet.getReceiveTxList();
        Iterator<ReceiveTransaction> it = txList.iterator();
        while (it.hasNext()) {
            ReceiveTransaction tx = it.next();
            if (tx.inSafe() || tx.isSpent()) {
                it.remove();
            } else {
                int depth = Parameters.wallet.getTxDepth(tx.getTxHash());
                if ((tx.isCoinBase() && depth < Parameters.COINBASE_MATURITY) ||
                                    (!tx.isCoinBase() && depth < 1)) {
                    it.remove();
                }
            }
        }
        //
        // Sort the unspent outputs based on their value
        //
        Collections.sort(txList, (ReceiveTransaction rcv1, ReceiveTransaction rcv2) ->
                                  rcv1.getValue().compareTo(rcv2.getValue()));
        //
        // Build the list of signed inputs
        //
        for (ReceiveTransaction rcvTx : txList) {
            byte[] scriptBytes = rcvTx.getScriptBytes();
            ECKey key = null;
            int paymentType = Script.getPaymentType(scriptBytes);
            if (paymentType == ScriptOpCodes.PAY_TO_PUBKEY_HASH) {
                byte[] pubKeyHash = Arrays.copyOfRange(scriptBytes, 3, 23);
                synchronized(Parameters.lock) {
                    for (ECKey chkKey : Parameters.keys) {
                        if (Arrays.equals(chkKey.getPubKeyHash(), pubKeyHash)) {
                            key = chkKey;
                            break;
                        }
                    }
                }
            } else if (paymentType == ScriptOpCodes.PAY_TO_SCRIPT_HASH) {    
                byte[] scriptHash = Arrays.copyOfRange(scriptBytes, 2, 22);
                synchronized(Parameters.lock) {
                    for (ECKey chkKey : Parameters.keys) {
                        if (Arrays.equals(chkKey.getScriptHash(), scriptHash)) {
                            key = chkKey;
                            break;
                        }
                    }
                }
            }
            if (key == null)
                throw new WalletException(String.format("No key available for transaction output\n  %s : %d",
                                                        rcvTx.getTxHash().toString(), rcvTx.getTxIndex()));
            OutPoint outPoint = new OutPoint(rcvTx.getTxHash(), rcvTx.getTxIndex());
            SignedInput input = new SignedInput(key, outPoint, rcvTx.getValue(), rcvTx.getScriptBytes());
            inputList.add(input);
        }
        //
        // Select coins if coin control specified
        //
        if (coinControl) {
            CoinControlDialog.showDialog(Main.mainWindow, inputList);
        }
        return inputList;
    }
}
