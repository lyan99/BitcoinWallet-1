/**
 * Copyright 2013-2014 Ronald W Hoffman
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
import org.ScripterRon.BitcoinCore.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Build the input list for a new transaction
 */
public class BuildInputList {

    /**
     * Build the signed input list for creating a new transaction.  The list will not
     * include unconfirmed transactions, spent transactions or transactions in the safe.
     *
     * @return                          Signed input list
     * @throws      WalletException     Unable to get list of unspent outputs
     */
    public static List<SignedInput> buildSignedInputs() throws WalletException {
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
                                    (!tx.isCoinBase() && depth < Parameters.TRANSACTION_CONFIRMED)) {
                    it.remove();
                }
            }
        }
        //
        // Sort the unspent outputs based on their value
        //
        Collections.sort(txList, new Comparator<ReceiveTransaction>() {
            @Override
            public int compare(ReceiveTransaction rcv1, ReceiveTransaction rcv2) {
                return rcv1.getValue().compareTo(rcv2.getValue());
            }
        });
        //
        // Build the list of signed inputs
        //
        for (ReceiveTransaction rcvTx : txList) {
            Address outAddress = rcvTx.getAddress();
            ECKey key = null;
            for (ECKey chkKey : Parameters.keys) {
                if (Arrays.equals(chkKey.getPubKeyHash(), outAddress.getHash())) {
                    key = chkKey;
                    break;
                }
            }
            if (key == null)
                throw new WalletException(String.format("No key available for transaction output\n  %s : %d",
                                                        rcvTx.getTxHash().toString(), rcvTx.getTxIndex()));
            OutPoint outPoint = new OutPoint(rcvTx.getTxHash(), rcvTx.getTxIndex());
            SignedInput input = new SignedInput(key, outPoint, rcvTx.getValue(), rcvTx.getScriptBytes());
            inputList.add(input);
        }
        return inputList;
    }
}
