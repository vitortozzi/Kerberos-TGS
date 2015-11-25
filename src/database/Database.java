/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package database;

import java.util.HashMap;

/**
 *
 * @author Vitor Tozzi
 */
public class Database {


    public HashMap<String, String> map;

    // TODO Utilizar hash nas senhas
    
    public Database() {
        map = new HashMap<>();
        map.put("cliente", "4983a0ab");
        map.put("tgs", "b8e0e9cc");
        map.put("server", "cf1e8c14");
    }
    
    

}
