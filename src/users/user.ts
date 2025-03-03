import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { 
  createRandomSymmetricKey, 
  exportSymKey, 
  importPubKey, 
  rsaEncrypt, 
  symEncrypt 
} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // State variables
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  // Status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });
  
  // Routes for last message info
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });
  
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });
  
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });
  
  // Message route for receiving
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });
  
  // Route for sending messages through the onion network
  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId } = req.body as SendMessageBody;
      lastSentMessage = message;
      
      // Get the node registry
      const registry = await fetch(`http://localhost:8080/getNodeRegistry`)
        .then(res => res.json())
        .then(json => (json as { nodes: any[] }).nodes);
      
      // Create a random circuit of 3 distinct nodes
      const nodeIds = registry.map(node => node.nodeId);
      const circuit = getRandomCircuit(nodeIds, 3);
      lastCircuit = circuit;
      
      // Final destination is the target user
      const finalDestination = BASE_USER_PORT + destinationUserId;
      
      // Build the onion in reverse (from innermost to outermost layer)
      let currentMessage = message;
      let currentDestination = finalDestination;
      
      // For each node in the circuit (in reverse)
      for (let i = circuit.length - 1; i >= 0; i--) {
        // Get current node from registry
        const currentNodeId = circuit[i];
        const currentNode = registry.find(n => n.nodeId === currentNodeId);
        
        if (!currentNode) {
          throw new Error(`Node ${currentNodeId} not found in registry`);
        }
        
        // 1. Prepend the destination to the message (padded to 10 chars)
        const paddedDestination = currentDestination.toString().padStart(10, '0');
        const dataToEncrypt = paddedDestination + currentMessage;
        
        // 2. Create a symmetric key for this layer
        const symmetricKey = await createRandomSymmetricKey();
        const symmetricKeyStr = await exportSymKey(symmetricKey);
        
        // 3. Encrypt the data with the symmetric key
        const encryptedData = await symEncrypt(symmetricKey, dataToEncrypt);
        
        // 4. Encrypt the symmetric key with the node's public key
        const encryptedKey = await rsaEncrypt(symmetricKeyStr, currentNode.pubKey);
        
        // 5. Combine the encrypted key and data for this layer
        currentMessage = encryptedKey + encryptedData;
        
        // The next iteration's destination is this node
        currentDestination = BASE_ONION_ROUTER_PORT + currentNodeId;
      }
      
      // Send the final multi-layered encrypted message to the first node
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0]}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: currentMessage
        })
      });
      
      res.send("success");
    } catch (error) {
      console.error(`Error sending message from user ${userId}:`, error);
      res.status(500).send("error");
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}

// Helper function to get random circuit
function getRandomCircuit(nodeIds: number[], length: number): number[] {
  if (nodeIds.length < length) {
    throw new Error('Not enough nodes to create a circuit');
  }
  
  const shuffled = [...nodeIds].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, length);
}