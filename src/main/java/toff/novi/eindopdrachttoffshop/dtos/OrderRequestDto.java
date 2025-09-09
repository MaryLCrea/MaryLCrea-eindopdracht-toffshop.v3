package toff.novi.eindopdrachttoffshop.dtos;

import java.util.List;

public class OrderRequestDto {
    private List<OrderItemRequestDto> items;


    public List<OrderItemRequestDto> getItems() {
        return items;
    }

    public void setItems(List<OrderItemRequestDto> items) {
        this.items = items;
    }
}
