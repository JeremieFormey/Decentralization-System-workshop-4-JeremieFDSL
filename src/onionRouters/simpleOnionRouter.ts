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

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  
  const keyPair = await generateRsaKeyPair();
  const publicKey = await exportPubKey(keyPair.publicKey);
  const privateKey = keyPair.privateKey;
  
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

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });
  
  onionRouter.get("/getPrivateKey", async (req, res) => {
    const exportedKey = await exportPrvKey(privateKey);
    res.json({ result: exportedKey });
  });
  
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });
  
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });
  
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });
  
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      lastReceivedEncryptedMessage = message;
      
      const keyBlockSize = 344;
      const encryptedSymKey = message.substring(0, keyBlockSize);
      const encryptedContent = message.substring(keyBlockSize);
      
      const symKey = await rsaDecrypt(encryptedSymKey, privateKey);
      
      const decryptedContent = await symDecrypt(symKey, encryptedContent);
      lastReceivedDecryptedMessage = decryptedContent;
      
      const destinationStr = decryptedContent.substring(0, 10);
      const remainingMessage = decryptedContent.substring(10);
      
      const destinationPort = parseInt(destinationStr);
      lastMessageDestination = destinationPort;
      
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
