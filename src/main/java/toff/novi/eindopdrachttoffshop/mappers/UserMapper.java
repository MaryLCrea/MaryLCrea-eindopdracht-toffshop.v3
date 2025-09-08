package toff.novi.eindopdrachttoffshop.mappers;

import toff.novi.eindopdrachttoffshop.dtos.UserRequestDto;
import toff.novi.eindopdrachttoffshop.dtos.UserResponseDto;
import toff.novi.eindopdrachttoffshop.models.User;

public class UserMapper {

    public static User toEntity(UserRequestDto userRequestDto) {
        User user = new User(
                userRequestDto.getName(),
                userRequestDto.getEmail(),
                userRequestDto.getPassword()
        );
        return user;
    }

    public static UserResponseDto toResponseDto(User user) {
        UserResponseDto userResponseDto = new UserResponseDto(user);
        userResponseDto.id = user.getId();
        userResponseDto.name = user.getName();
        userResponseDto.email = user.getEmail();
        return userResponseDto;
    }
}


