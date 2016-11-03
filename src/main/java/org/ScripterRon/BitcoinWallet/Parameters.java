/**
 * Copyright 2013-2016 Ronald W Hoffman
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

import org.ScripterRon.BitcoinCore.Address;
import org.ScripterRon.BitcoinCore.BloomFilter;
import org.ScripterRon.BitcoinCore.ECKey;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.MessageListener;
import org.ScripterRon.BitcoinCore.PeerAddress;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

/**
 * Global parameters for BitcoinWallet
 */
public class Parameters {

    /** Minimum supported protocol level (we require SPV support) */
    public static final int MIN_PROTOCOL_VERSION = 70001;

    /** Default network port */
    public static final int DEFAULT_PORT = 8333;

    /** Software identifier */
    public static String SOFTWARE_NAME = "BitcoinWallet:?.?";

    /** Genesis block bytes */
    public static byte[] GENESIS_BLOCK_BYTES;

    /** Minimum transaction fee */
    public static final BigInteger MIN_TX_FEE = new BigInteger("1000", 10);

    /** Dust transaction value */
    public static final BigInteger DUST_TRANSACTION = new BigInteger("546", 10);

    /** Maximum ban score before a peer is disconnected */
    public static final int MAX_BAN_SCORE = 100;

    /** Coinbase transaction maturity */
    public static final int COINBASE_MATURITY = 120;

    /** Transaction maturity */
    public static final int TRANSACTION_CONFIRMED = 2;

    /** Short-term lock object */
    public static final Object lock = new Object();

    /** Message handler queue */
    public static final ArrayBlockingQueue<Message> messageQueue = new ArrayBlockingQueue<>(50);

    /** Database handler queue */
    public static final ArrayBlockingQueue<Object> databaseQueue = new ArrayBlockingQueue<>(50);

    /** Peer addresses */
    public static final List<PeerAddress> peerAddresses = new LinkedList<>();

    /** Peer address map */
    public static final Map<PeerAddress, PeerAddress> peerMap = new HashMap<>();

    /** Completed messages */
    public static final List<Message> completedMessages = new ArrayList<>(50);

    /** List of peer requests that are waiting to be sent */
    public static final List<PeerRequest> pendingRequests = new ArrayList<>(50);

    /** List of peer requests that are waiting for a response */
    public static final List<PeerRequest> processedRequests = new ArrayList<>(50);

    /** Network handler */
    public static NetworkHandler networkHandler;

    /** Database handler */
    public static DatabaseHandler databaseHandler;

    /** Inventory handler */
    public static MessageListener messageListener;

    /** Wallet database */
    public static Wallet wallet;

    /** Bloom filter */
    public static BloomFilter bloomFilter;

    /** Key list */
    public static List<ECKey> keys;

    /** Change key */
    public static ECKey changeKey;

    /** Address list */
    public static List<Address> addresses;

    /** Network chain height */
    public static int networkChainHeight;

    /** Loading block chain */
    public static boolean loadingChain = false;

    /** Wallet passphrase */
    public static String passPhrase;
}
