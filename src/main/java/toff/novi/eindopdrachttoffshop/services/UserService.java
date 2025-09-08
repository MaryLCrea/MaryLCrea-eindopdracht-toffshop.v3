package toff.novi.eindopdrachttoffshop.services;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import toff.novi.eindopdrachttoffshop.dtos.UserRequestDto;
import toff.novi.eindopdrachttoffshop.dtos.UserResponseDto;
import toff.novi.eindopdrachttoffshop.exceptions.ResourceNotFoundException;
import toff.novi.eindopdrachttoffshop.mappers.UserMapper;
import toff.novi.eindopdrachttoffshop.models.Role;
import toff.novi.eindopdrachttoffshop.models.User;
import toff.novi.eindopdrachttoffshop.repositories.RoleRepository;
import toff.novi.eindopdrachttoffshop.repositories.UserRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserResponseDto createUser(UserRequestDto userRequestDto) {
        if (userRepository.existsByEmail(userRequestDto.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = UserMapper.toEntity(userRequestDto);

        user.setPassword(passwordEncoder.encode(userRequestDto.getPassword()));

        Set<Role> roles = new HashSet<>();
        for (String roleName : userRequestDto.getRoles()) {
            Role role = roleRepository.findById("ROLE_" + roleName)
                    .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleName));
            roles.add(role);
        }
        user.setRoles(roles);

        User savedUser = userRepository.save(user);


        return UserMapper.toResponseDto(savedUser);
    }

    public User getSingleUser(Integer id) {
        return this.userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
    }

    public List<User> getUsers() {
        return userRepository.findAll();
    }

    public List<User> findAll() {
        return null;
    }

    public UserResponseDto updateUser(Integer id, UserRequestDto newUser) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        existingUser.setName(newUser.getName());
        existingUser.setEmail(newUser.getEmail());

        existingUser.setPassword(passwordEncoder.encode(newUser.getPassword()));


        User updatedUser = userRepository.save(existingUser);
        return UserMapper.toResponseDto(updatedUser);
    }

        public void deleteUser(int id) {
        userRepository.deleteById(id);
    }
}