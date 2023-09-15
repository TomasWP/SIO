function login(){

    var user = document.getElementById('login').value;
    var password = document.getElementById('password').value;

// Fazer uma solicitação para carregar o arquivo JSON
    fetch('users.json')
        .then(response => response.json())
        .then(users => {
            console.log(user.username);
            console.log(user.password);
            function verificarCredenciais(username, password) {
                for (const user of users) {
                  if (user.username === username && user.password === password) {
                    return true; // Credenciais corretas
                  }
                }
                return false; // Credenciais incorretas
            }
            // Verificar as credenciais inseridas pelo usuário
            if (verificarCredenciais(user, password)) {
                console.log("Login bem-sucedido!");
                location.href = "index.html";
            } else {
                console.log("Credenciais inválidas. Tente novamente.");
            }
        })
    .catch(error => {
        console.error("Erro ao carregar o arquivo JSON:", error);
    });
}

const loginButton = document.getElementById("loginButton");
loginButton.addEventListener("click", function (event) {
  event.preventDefault(); // Evite que o formulário seja enviado
  login(); // Chame a função de login
});

const loginForm = document.getElementById("loginForm");
loginForm.addEventListener("submit", function (event) {
  event.preventDefault(); // Evite que o formulário seja enviado
  login(); // Chame a função de login
});

  