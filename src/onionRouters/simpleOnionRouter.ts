import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";
import { 
  exportPrvKey, 
  generateRsaKeyPair, 
  exportPubKey, 
  rsaDecrypt, 
  symDecrypt 
} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // State variables to track the last message
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  
  // Generate key pair for this node
  const keyPair = await generateRsaKeyPair();
  const publicKey = await exportPubKey(keyPair.publicKey);
  const privateKey = keyPair.privateKey;
  
  // Register with the registry
  try {
    await fetch(`http://localhost:8080/registerNode`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        nodeId,
        pubKey: publicKey
      })
    });
  } catch (error) {
    console.error(`Error registering node ${nodeId}:`, error);
  }

  // Status route
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });
  
  // Get private key route for testing
  onionRouter.get("/getPrivateKey", async (req, res) => {
    const exportedKey = await exportPrvKey(privateKey);
    res.json({ result: exportedKey });
  });
  
  // Routes for last message info
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });
  
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });
  
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });
  
  // Message route for receiving and forwarding
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      lastReceivedEncryptedMessage = message;
      
      // In an onion network, each message has:
      // 1. RSA encrypted symmetric key (first part)
      // 2. Symmetrically encrypted content (second part)
      
      // Step 1: Extract the RSA encrypted symmetric key
      // RSA-OAEP with 2048 bits and SHA-256 produces consistent output length
      const keyBlockSize = 344; // for base64 encoded RSA-OAEP encrypted output (2048 bits)
      const encryptedSymKey = message.substring(0, keyBlockSize);
      const encryptedContent = message.substring(keyBlockSize);
      
      // Step 2: Decrypt the symmetric key using this node's private key
      const symKey = await rsaDecrypt(encryptedSymKey, privateKey);
      
      // Step 3: Use the symmetric key to decrypt the content
      const decryptedContent = await symDecrypt(symKey, encryptedContent);
      lastReceivedDecryptedMessage = decryptedContent;
      
      // Step 4: Parse the destination (first 10 characters) from the decrypted content
      const destinationStr = decryptedContent.substring(0, 10);
      const remainingMessage = decryptedContent.substring(10);
      
      const destinationPort = parseInt(destinationStr);
      lastMessageDestination = destinationPort;
      
      // Step 5: Forward the remaining message to the next destination
      await fetch(`http://localhost:${destinationPort}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: remainingMessage
        })
      });
      
      res.send("success");
    } catch (error) {
      console.error(`Error processing message at node ${nodeId}:`, error);
      res.status(500).send("error");
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}