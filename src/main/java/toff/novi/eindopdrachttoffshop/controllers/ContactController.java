package toff.novi.eindopdrachttoffshop.controllers;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import toff.novi.eindopdrachttoffshop.config.UriHelper;
import toff.novi.eindopdrachttoffshop.dtos.ContactRequestDto;
import toff.novi.eindopdrachttoffshop.dtos.ContactResponseDto;
import toff.novi.eindopdrachttoffshop.services.ContactService;

import java.net.URI;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/contacts")
public class ContactController {

    private final ContactService contactService;

    public ContactController(ContactService contactService) {
        this.contactService = contactService;
    }

    @PostMapping
    public ResponseEntity<List<ContactResponseDto>> createContacts(
            @Valid @RequestBody List<ContactRequestDto> contactRequestDtos) {

        List<ContactResponseDto> createdContacts = contactRequestDtos.stream()
                .map(contactService::createContact)
                .toList();
        URI uri = createdContacts.isEmpty() ? null :
                UriHelper.createUri("contacts", String.valueOf(createdContacts.get(0).getId()));
        return ResponseEntity.created(uri).body(createdContacts);
    }

    @GetMapping
    public ResponseEntity<List<ContactResponseDto>> getAllContacts() {
        List<ContactResponseDto> contacts = contactService.getAllContacts();
        return ResponseEntity.ok(contacts);
    }

    @GetMapping("/unread")
    public ResponseEntity<List<ContactResponseDto>> getUnreadContacts() {
        List<ContactResponseDto> contacts = contactService.getUnreadContacts();
        return ResponseEntity.ok(contacts);
    }

    @GetMapping("/read")
    public ResponseEntity<List<ContactResponseDto>> getReadContacts() {
        List<ContactResponseDto> contacts = contactService.getReadContacts();
        return ResponseEntity.ok(contacts);
    }

    @GetMapping("/unread/count")
    public ResponseEntity<Map<String, Long>> getUnreadCount() {
        long count = contactService.getUnreadCount();
        return ResponseEntity.ok(Map.of("unreadCount", count));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ContactResponseDto> getContactById(@PathVariable Integer id) {
        ContactResponseDto contact = contactService.getContactById(id);
        return ResponseEntity.ok(contact);
    }

    @GetMapping("/search")
    public ResponseEntity<List<ContactResponseDto>> searchBySubject(@RequestParam String subject) {
        List<ContactResponseDto> contacts = contactService.searchBySubject(subject);
        return ResponseEntity.ok(contacts);
    }

    @PatchMapping("/{id}/read")
    public ResponseEntity<ContactResponseDto> markAsRead(@PathVariable Integer id) {
        ContactResponseDto updatedContact = contactService.markAsRead(id);
        return ResponseEntity.ok(updatedContact);
    }

    @PatchMapping("/{id}/unread")
    public ResponseEntity<ContactResponseDto> markAsUnread(@PathVariable Integer id) {
        ContactResponseDto updatedContact = contactService.markAsUnread(id);
        return ResponseEntity.ok(updatedContact);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteContact(@PathVariable Integer id) {
        contactService.deleteContact(id);
        return ResponseEntity.noContent().build();
    }
}
