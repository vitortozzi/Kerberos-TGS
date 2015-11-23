/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kerberos;

import java.io.IOException;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JOptionPane;
import message.ASTicket;
import message.ServerTicket;
import message.TGSRequest;
import message.TGSResponse;
import utils.FileUtils;
import utils.HashUtils;
import utils.TimeUtils;

/**
 *
 * @author Vitor Tozzi
 */
public class ImplementTGS extends UnicastRemoteObject implements InterfaceTGS {

    String senhaTGS = "tgs12345";
    String senhaServer = "server12";

    public ImplementTGS() throws RemoteException {
        super();
    }

    @Override
    public void readTicketFromClient(String filepath) {

        FileUtils fileUtils;
        try {
            fileUtils = new FileUtils(senhaTGS);
            ASTicket aSTicket = (ASTicket) fileUtils.readEncryptedObject(filepath);

            String sessionKey = aSTicket.sessionKey;

            String tgsRequestFilePath = "F:\\Kerberos\\TGS\\clientRequest.des";
            fileUtils = new FileUtils(sessionKey);
            TGSRequest tGSRequest = (TGSRequest) fileUtils.readEncryptedObject(tgsRequestFilePath);

            System.out.println("***Passo 3: TGS lê ticket vindo do AS e requisição de servido do cliente");
            aSTicket.print();
            tGSRequest.print();

            // Verifica se o ticket ainda é válido
            if (!TimeUtils.checkValidTimestamp(tGSRequest.timestamp)) {
                JOptionPane.showMessageDialog(null, "O ticket do cliente ao TGS está fora do prazo de validade.");
            } else {
                /**
                 * Salva no cliente o ticket para utilização com o Servidor
                 */

                String clientID = aSTicket.clientID;
                String serviceID = "servidor";
                String randomNumber = tGSRequest.randomNumber;

                String newSessionKey = HashUtils.generateSessionKey(clientID + serviceID);

                // Objeto criado para ser encriptado e salvo no cliente
                TGSResponse tGSResponse = new TGSResponse(newSessionKey, randomNumber);
                String tgsResponseFilepath = "F:\\Kerberos\\Client\\tgsResponse.des";
                System.out.println("Responde gerado no TGS");
                tGSResponse.print();

                // Encripta o arquivo com a chave de sessão Cliente - TGS
                fileUtils.writeEncryptedObject(tGSResponse, tgsResponseFilepath);

                /**
                 * Agora será gerado o ticket para o servico do servidor
                 */
                Date timestamp = TimeUtils.addHours(TimeUtils.getDate(), 2);
                ServerTicket serverTicket = new ServerTicket(clientID, timestamp, serviceID, newSessionKey);
                String serverTicketToClientFilepah = "F:\\Kerberos\\Client\\serverTicket.des";

                fileUtils = new FileUtils(senhaServer);
                fileUtils.writeEncryptedObject(serverTicket, serverTicketToClientFilepah);
            }

        } catch (InvalidKeyException ex) {
            Logger.getLogger(ImplementTGS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ImplementTGS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(ImplementTGS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(ImplementTGS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ImplementTGS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ImplementTGS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public String sayHello() throws RemoteException {
        return "O Servidor TGS disse oi =)";
    }

    public static void main(String[] args) throws RemoteException {
        int port = 9797;
        String thisAddress;
        try {
            thisAddress = (InetAddress.getLocalHost()).toString();
        } catch (Exception e) {
            throw new RemoteException("Não foi possível pegar o endereço.");
        }

        System.out.println("Endereço IP:" + thisAddress + " ---- Porta: " + port);
        try {
            // Cria o registro
            Registry registry = LocateRegistry.createRegistry(port);
            // Instancia o objeto das implementações do servidor
            ImplementTGS interfaceTGS = new ImplementTGS();
            // Liga o servidor a TAG, para que o cliente possa encontra-lo
            registry.bind("HelloServer", interfaceTGS);
            /**
             * Inicia banco de dados com senha dos usuários
             */

        } catch (Exception e) {
            System.out.println("Erro " + e.getMessage());
        }
    }

}
