package uk.gov.hmcts.dm.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import uk.gov.hmcts.dm.config.V1MediaType;
import uk.gov.hmcts.dm.domain.Folder;
import uk.gov.hmcts.dm.hateos.FolderHalResource;
import uk.gov.hmcts.dm.service.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping(
    path = "/folders",
    produces = V1MediaType.V1_FOLDER_MEDIA_TYPE_VALUE)
@Api("Endpoint for Folder management")
@ConditionalOnProperty("toggle.folderendpoint")
public class FolderController {

    @Autowired
    private FolderService folderService;

    @Autowired
    private StoredDocumentService storedDocumentService;

    @PostMapping("")
    @ApiOperation("Create a Folder.")
    public ResponseEntity<FolderHalResource> post(@RequestBody FolderHalResource folderHalResource) {
        Folder folder = new Folder();
        folderService.save(folder);
        return ResponseEntity.ok(new FolderHalResource(folder));
    }

    @PostMapping(value = "/{id}/documents", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ApiOperation("Adds a list of Stored Documents to a Folder (Stored Documents are created from uploaded Documents)")
    public ResponseEntity<Object> addDocuments(@PathVariable UUID id, @RequestParam List<MultipartFile> files) {

        return folderService.findById(id)
            .map( folder -> {
                storedDocumentService.saveItemsToBucket(folder, files);
                return ResponseEntity.noContent().build();
            })
            .orElse(ResponseEntity.notFound().build());

    }

    @GetMapping("{id}")
    @ApiOperation("Retrieves JSON representation of a Folder.")
    public ResponseEntity<?> get(@PathVariable UUID id) {
        return folderService
            .findById(id)
            .map(FolderHalResource::new)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.noContent().build());
    }

    @DeleteMapping("{id}")
    @ApiOperation("Deletes a Folder.")
    public ResponseEntity<Object> delete(@PathVariable UUID id) {
        return ResponseEntity.status(405).build();
    }

}
