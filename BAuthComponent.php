<?php
/**
 * This component implements bcrypt and is used similarily like CakePHP's
 * Auth-component.
 * 
 * By default, this component allows MD5(password)s for convience. It will
 * rehash them when logging in.
 */
class BAuthComponent extends Object {

    var $components = array('Session');
    var $settings;
    var $controller;

    function initialize(&$controller, $settings = array()) {
        $this->controller = &$controller;
        $this->Session = $this->controller->Session;
        $default = array(
            'difficulty' => 8,
            'debug' => false,
            'check_email' => true
        );
        $settings = array_merge($default, $settings);
        $this->settings = $settings;
        $this->isDebug = $this->settings['debug'];
    }

    function startup() {
        
    }

    function beforeRender() {
        
    }

    function shutdown() {
        
    }

    function login_as($id) {
        $user = ClassRegistry::init('User')->findById($id);
        $this->Session->write('Auth.User', $user['User']);
        return true;
    }

    function hash($password) {
        App::import('Vendor', 'phpass', array('file' => 'phpass-0.3' . DS . 'PasswordHash.php'));
        $PasswordHash = new PasswordHash($this->settings['difficulty'], false);
        return $PasswordHash;
    }

    function isLogged() {
        return is_array($this->Session->write('Auth.User'));
    }

    function logout() {
        $this->Session->delete('Auth.User');
    }

    function login() {
        $User = ClassRegistry::init('User');
        App::import('Vendor', 'phpass', array('file' => 'phpass-0.3' . DS . 'PasswordHash.php'));
        if ($this->settings['check_email'] === true) {
            $user = $User->find('first', array('conditions' => array(
                    'OR' => array(
                        'User.username' => $this->controller->request->data['User']['username'],
                        'User.email' => $this->controller->request->data['User']['username'],
                    )
                    )));
        } else {
            $user = $User->find('first', array('conditions' => array(
                    'OR' => array(
                        'User.username' => $this->controller->request->data['User']['username']
                    )
                    )));
        }

        $password = $this->controller->request->data['User']['password'];
        $PasswordHash = new PasswordHash($this->settings['difficulty'], false);
        //$hash = $PasswordHash->HashPassword($this->controller->request->data['User']['password']);

        if ($this->isDebug)
            debug('BAuthComponent: Logging as ' . $this->controller->request->data['User']['username'] . ' with password ' . $this->controller->request->data['User']['password']);

        if (!$user) {
            return 'username_not_found';
        } elseif (md5($password) == $user['User']['password']) {
            $User->id = $user['User']['id'];
            $data = array('User' => array('password' => $PasswordHash->HashPassword($password)));
            $User->save($data, array('validate' => false, 'callbacks' => false));
            $this->login_as($user['User']['id']);
            return 'success';
        } elseif ($PasswordHash->CheckPassword($password, $user['User']['password'])) {
            $this->login_as($user['User']['id']);
            return 'success';
        } else {
            return 'error';
        }
    }

}

?>