    function addToCart(event) {

        const existingCartItem = cart.find(item => item.id === productId);

        if (existingCartItem) {
            existingCartItem.quantity++;
        } else {
            cart.push({ id: productId, name: productName, price: productPrice, quantity: 1 });
        }
        total += price;
        updateCart();
    }

    function updateCart() {
        const carrinhoList = document.getElementById('carrinho');
        const totalElement = document.getElementById('total');
        let total = 0;
        carrinhoList.innerHTML = '';
        
        carrinho.forEach(item => {
            const listItem = document.createElement('li');
            listItem.textContent = `${item.nome} - $${item.preco}`;
            carrinhoList.appendChild(listItem);
            total += item.preco;
        });
        
        totalElement.textContent = total;
    }
