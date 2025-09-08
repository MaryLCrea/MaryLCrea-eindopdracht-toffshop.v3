package toff.novi.eindopdrachttoffshop.controllers;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import toff.novi.eindopdrachttoffshop.config.UriHelper;
import toff.novi.eindopdrachttoffshop.dtos.UserRequestDto;
import toff.novi.eindopdrachttoffshop.dtos.UserResponseDto;
import toff.novi.eindopdrachttoffshop.models.User;
import toff.novi.eindopdrachttoffshop.services.UserService;
import toff.novi.eindopdrachttoffshop.mappers.UserMapper;


import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {

        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<List<UserResponseDto>> createUsers(@Valid @RequestBody List<UserRequestDto> userRequestDtos) {
        List<UserResponseDto> responseDtos = userRequestDtos.stream()
                .map(userService::createUser)
                .toList();

        URI uri = responseDtos.isEmpty() ? null :
                UriHelper.createUri("users", String.valueOf(responseDtos.get(0).getId()));

        return ResponseEntity.created(uri).body(responseDtos);
    }


    @GetMapping
    public List<UserResponseDto> getAllUsers() {
        List<User> users = userService.getUsers();

        return users.stream()
                .map(UserResponseDto::new)
                .collect(Collectors.toList());
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Integer id) {
        return ResponseEntity.ok(UserMapper.toResponseDto(this.userService.getSingleUser(id)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Object> deleteUser(@PathVariable Integer id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserResponseDto> updateUser(@PathVariable Integer id, @Valid @RequestBody UserRequestDto newUser) {

        UserResponseDto dto = userService.updateUser(id, newUser);

        return ResponseEntity.ok().body(dto);
    }
}