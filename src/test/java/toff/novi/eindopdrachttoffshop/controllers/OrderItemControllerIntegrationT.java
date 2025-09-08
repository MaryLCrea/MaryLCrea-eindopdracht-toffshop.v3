package toff.novi.eindopdrachttoffshop.controllers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import toff.novi.eindopdrachttoffshop.dtos.CartResponseDto;
import toff.novi.eindopdrachttoffshop.dtos.UserRequestDto;
import toff.novi.eindopdrachttoffshop.dtos.UserResponseDto;
import toff.novi.eindopdrachttoffshop.models.User;
import toff.novi.eindopdrachttoffshop.services.CartService;
import toff.novi.eindopdrachttoffshop.services.UserService;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class OrderItemControllerIntegrationT {

    @Autowired
    private UserService userService;


    private CartService cartService;

    private UserResponseDto testUser;

    @BeforeEach
    void setUp() {
        UserRequestDto userRequest = new UserRequestDto();
        userRequest.setName("Alex Puk");
        userRequest.setEmail("alex@email.com");
        userRequest.setPassword("password123");

        testUser = userService.createUser(userRequest);
    }

    @Test
    void testAddSingleItemToCart() {
        CartResponseDto cart = cartService.addOrderItem(
                testUser.getId(),
                "Dansschoenen",
                new BigDecimal("79.99"),
                2
        );

        assertThat(cart).isNotNull();
        assertThat(cart.getCartItems()).hasSize(1);
        assertThat(cart.getCartItems().getFirst().getProductName()).isEqualTo("Dansschoenen");
        assertThat(cart.getCartItems().getFirst().getQuantity()).isEqualTo(2);
        assertThat(cart.getTotalAmount()).isEqualTo(new BigDecimal("159.98"));
    }

    @Test
    void testAddMultipleItemsToCart() {
        cartService.addOrderItem(testUser.getId(), "Dansschoenen Zwart", new BigDecimal("89.99"), 1);
        CartResponseDto cart = cartService.addOrderItem(testUser.getId(), "Dansschoenen Wit", new BigDecimal("95.99"), 1);

        assertThat(cart.getCartItems()).hasSize(2);
        assertThat(cart.getTotalAmount()).isEqualTo(new BigDecimal("185.98"));
    }

    @Test
    void testGetCartByUserId() {
        CartResponseDto cart = cartService.getCartByUserId(testUser.getId());

        assertThat(cart).isNotNull();
        assertThat(cart.getUserId()).isEqualTo(testUser.getId());
        assertThat(cart.getCartItems()).isEmpty();
    }
}


