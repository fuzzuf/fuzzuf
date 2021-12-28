#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#define VERSION "1.0"
#define RELEASE_DATE "Dec 14th 2021"

#ifndef bool
#define bool  char
#define true  1
#define false 0
#endif

/* Define markers */
#define JPEG_MARKER_SOI  ((u8)0xD8)
#define JPEG_MARKER_EOI  ((u8)0xD9)
#define JPEG_MARKER_SOS  ((u8)0xDA)
#define JPEG_MARKER_RST0 ((u8)0xD0)
#define JPEG_MARKER_RST7 ((u8)0xD7)
#define JPEG_MARKER_APP1 ((u8)0xE1)

/* EXIF constants*/
#define JPEG_EXIF_IDENTIFIER     "Exif\0\0"
#define JPEG_EXIF_IDENTIFIER_LEN 6
#define JPEG_XMP_IDENTIFIER      "http:"
#define JPEG_XMP_IDENTIFIER_LEN  5
#define JPEG_TIFF_BE        ((u16)0x4D4D)
#define JPEG_TIFF_TYPE_TIFF ((u16)0x2A)
/* TagID */
#define JPEG_EXIF_TAGID_IMAGEWIDTH    256
#define JPEG_EXIF_TAGID_IMAGELENGTH   257
#define JPEG_EXIF_TAGID_IMAGEDESC     270
#define JPEG_EXIF_TAGID_MAKER         271
#define JPEG_EXIF_TAGID_MODEL         272
#define JPEG_EXIF_TAGID_ORIENTATION   274
#define JPEG_EXIF_TAGID_XRESOLUTION   282
#define JPEG_EXIF_TAGID_YRESOLUTION   283
#define JPEG_EXIF_TAGID_RESUNIT       296
#define JPEG_EXIF_TAGID_CREATORTOOL   305
#define JPEG_EXIF_TAGID_MODIFYDATE    306
#define JPEG_EXIF_TAGID_ARTIST        315
#define JPEG_EXIF_TAGID_COPYRIGHT     33432
#define JPEG_EXIF_TAGID_EXIF_IFD      34665
#define JPEG_EXIF_TAGID_GPS_IFD       34853
#define JPEG_EXIF_TAGID_EXIF_VERSION  36864
#define JPEG_EXIF_TAGID_EXIF_IIFD     40965
/* Data type */
#define JPEG_EXIF_DATATYPE_BYTE      1
#define JPEG_EXIF_DATATYPE_ASCII     2
#define JPEG_EXIF_DATATYPE_SHORT     3
#define JPEG_EXIF_DATATYPE_LONG      4
#define JPEG_EXIF_DATATYPE_RATIONAL  5
#define JPEG_EXIF_DATATYPE_SBYTE     6
#define JPEG_EXIF_DATATYPE_UNDEFINED 7
#define JPEG_EXIF_DATATYPE_SSHORT    8
#define JPEG_EXIF_DATATYPE_SLONG     9
#define JPEG_EXIF_DATATYPE_SRATIONAL 10
#define JPEG_EXIF_DATATYPE_FLOAT     11
#define JPEG_EXIF_DATATYPE_DFLOAT    12
const int JPEG_EXIF_DATATYPE_SIZE[] = {
  0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8
};

/* Define structures */
typedef long long s64;
typedef int       s32;
typedef short     s16;
typedef char      s8;
typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned short     u16;
typedef unsigned char      u8;

typedef struct _jpeg_file_t {
  FILE *file;
  char *path;
  bool (**ops)(struct _jpeg_file_t*);
} jpeg_file_t;

typedef bool (**jpeg_ops_t)(jpeg_file_t*);

/* Exif structus */
typedef struct __attribute__((packed)) {
  u16 order;
  u16 type;
  u32 ifd_offset;
} tiff_header_t;

typedef struct __attribute__((packed)) {
  u16 tag;
  u16 type;
  u32 count;
  u32 offset;
} tiff_entry_t;

typedef struct {
  u16 type;
  u32 count;
  union {
    void *ptr; /* generic pointer */
    u8  *byte_vec;
    u8  *ascii;
    u8  *undefined_vec;
    u16 *short_vec;
    u32 *long_vec;
    u32 *rational_vec;
    float  *float_vec;
    double *double_vec;
  };
} tiff_data_t;

/* JPEG parser */
jpeg_file_t *jpeg_file_load (const char*, jpeg_ops_t);
bool jpeg_walk (jpeg_file_t*);
void jpeg_file_release (jpeg_file_t*);
/* Segment hanglers */
jpeg_ops_t jpeg_new_handler (void);
bool jpeg_seghandler_default (jpeg_file_t*);
bool jpeg_seghandler_skip_sos (jpeg_file_t*);

/**
 * Utility to convert endianness
 */
void be16_to_cpu(u16 *v) {
  *v =
    ((*v & 0xFF00) >> 8) |
    ((*v & 0x00FF) << 8);
}

void be32_to_cpu(u32 *v) {
  *v =
    ((*v & 0xFF000000) >> 24) |
    ((*v & 0x00FF0000) >> 8 ) |
    ((*v & 0x0000FF00) << 8 ) |
    ((*v & 0x000000FF) << 24);
}

void be64_to_cpu(u64 *v) {
  *v =
    ((*v & 0xFF00000000000000LL) >> 56) |
    ((*v & 0x00FF000000000000LL) >> 40) |
    ((*v & 0x0000FF0000000000LL) << 24) |
    ((*v & 0x000000FF00000000LL) << 8 ) |
    ((*v & 0x00000000FF000000LL) << 8 ) |
    ((*v & 0x0000000000FF0000LL) << 24) |
    ((*v & 0x000000000000FF00LL) << 40) |
    ((*v & 0x00000000000000FFLL) << 56);
}

/**
 * Load JPEG file
 */
jpeg_file_t *jpeg_file_load (const char *filepath, jpeg_ops_t ops)
{
  FILE *fp;
  jpeg_file_t *jpeg;

  /* Open file */
  if (!(fp = fopen(filepath, "rb"))) {
    perror(filepath);
    return NULL;
  }

  /* Allocate jpeg file structure */
  if (!(jpeg = (jpeg_file_t*)calloc(sizeof(jpeg_file_t), 1))) {
    perror("Memory error");
    return NULL;
  }
  jpeg->file = fp;
  jpeg->ops = ops;

  /* Copy filepath */
  if (!(jpeg->path = strdup(filepath))) {
    perror("Memory error");
    jpeg_file_release(jpeg);
    return NULL;
  }

  return jpeg;
}

/**
 * Parse JPEG file and call handler for each segment
 */
bool jpeg_walk (jpeg_file_t *jpeg)
{
  bool encount_soi;
  u8 marker[2];

  fseek(jpeg->file, 0, SEEK_SET);

  /* Read every segment */
  encount_soi = false;
  while (!feof(jpeg->file)) {
    /* Read marker */
    if (fread(marker, sizeof(marker), 1, jpeg->file) != 1) {
      fputs("Truncated file (broken marker)\n", stderr);
      return encount_soi; /* Return false only if it's not JPEG */
    }

    if (marker[0] != 0xFF) {
      fputs("Invalid marker (Corrupted JPEG)\n", stderr);
      return encount_soi; /* Return false only if it's not JPEG */
    }

    /* Handle special markers */
    if (marker[1] == JPEG_MARKER_SOI) {

      /* Start of image segment */
      if (encount_soi)
        /* Skip the segment if we encounter SOI at invalid position */
        fputs("SOI at invalid position\n", stderr);
      else
        encount_soi = true;

      continue;

    } else if (!encount_soi) {

      /* Abort if the first segment is not SOI */
      fputs("Not a valid JPEG file\n", stderr);
      return false;

    } else if (marker[1] == JPEG_MARKER_EOI) {

      /* End of image segment */
      return true;

    }

    /* Call handler for each segment */
    if (jpeg->ops[marker[1]]) {
      if (!jpeg->ops[marker[1]](jpeg))
        return false;
    }
  }

  /* Reached end of file before EOI segment */
  fputs("Truncated file (EOI not found)\n", stderr);
  return true;
}

/**
 * Release JPEG file structure
 */
void jpeg_file_release (jpeg_file_t *jpeg)
{
  if (jpeg->file) /* File */
    fclose(jpeg->file);

  free(jpeg->path); /* Filepath */
  free(jpeg);
}

/**
 * Create the default handler table
 */
jpeg_ops_t jpeg_handlers_new (void)
{
  int i;
  jpeg_ops_t ops;

  ops = (jpeg_ops_t)malloc(sizeof(void*) * 0x100);
  for (i = 0; i < 0x100; i++) {
    ops[i] = &jpeg_seghandler_default;
  }

  /* SOS marker is exceptional */
  ops[JPEG_MARKER_SOS] = jpeg_seghandler_skip_sos;

  return ops;
}

/**
 * Release handler table
 */
void jpeg_handlers_release (jpeg_ops_t ops)
{
  free(ops);
}

/**
 * Default handler for SOS segment
 */
bool jpeg_seghandler_skip_sos (jpeg_file_t *jpeg)
{
  u8 c;
  u16 len_field;

  /* Read the length of this segment */
  if (fread(&len_field, sizeof(len_field), 1, jpeg->file) != 1) {
    fputs("Truncated file\n", stderr);
    return false;
  }
  be16_to_cpu(&len_field);

  /* Skip this segment */
  fseek(jpeg->file, len_field - sizeof(len_field), SEEK_CUR);

  /* Search for next segment marker */
  while (!feof(jpeg->file)) {
    if (fread(&c, sizeof(u8), 1, jpeg->file) != 1)
      break;

    if (c == 0xFF) {
      /* Check if this is a marker (or encoded 0xFF) */
      if (fread(&c, sizeof(u8), 1, jpeg->file) != 1)
        break;

      if (c == 0x00) {
        /* Byte stuffing (encoded 0xFF) */
        continue;

      } else if (JPEG_MARKER_RST0 <= c && c <= JPEG_MARKER_RST7) {
        /* Ignore reset markers */
        continue;

      } else {
        /* Found next marker */
        fseek(jpeg->file, -2 * sizeof(u8), SEEK_CUR);
        return true;
      }
    }
  }

  /* [TODO] Is there any case SOS is the last segment? */
  fputs("Truncated file (End of SOS not found)\n", stderr);
  return false;
}

/**
 * Parse an EXIF entry
 */
tiff_data_t *jpeg_exif_read_entry (tiff_entry_t *entry, u8 *ifd, bool is_be, u16 len_ifd)
{
  u16 t16;
  u32 i, size, unitsize, t32;
  u64 t64;
  void *srcptr;
  tiff_data_t *data;

  /* Check data type */
  if (!(entry->type >= JPEG_EXIF_DATATYPE_BYTE &&
        entry->type <= JPEG_EXIF_DATATYPE_DFLOAT)) {
    fputs("Invalid data type\n", stderr);
    return NULL;
  }
  unitsize = JPEG_EXIF_DATATYPE_SIZE[entry->type];

  /* Allocate buffer for data */
  data = (tiff_data_t*)malloc(sizeof(tiff_data_t));
  if (!data) {
    perror("Memory error");
    return NULL;
  }
  data->type = entry->type;
  data->count = entry->count;

  /* Calculate required size and allocate buffer */
  size = unitsize * entry->count;
  if (entry->type == JPEG_EXIF_DATATYPE_ASCII) /* Add space for NULL */
    data->ptr = malloc(size + 1);
  else
    data->ptr = malloc(size);
  if (!data->ptr) {
    perror("Memory error");
    free(data);
    return NULL;
  }

  /* Calculate the pointer of data source */
  if (size <= 4) {
    /* If size is less than 5 byte, data is stored in offset field */
    if (is_be)
      be32_to_cpu(&entry->offset);
    srcptr = &entry->offset;
  } else {
    if (entry->offset + size > len_ifd) {
      /* Out-of-bounds */
      fputs("Invalid data offset or size\n", stderr);
      free(data->ptr);
      free(data);
      return NULL;
    }
    srcptr = (void*)ifd + entry->offset;
  }

  /* Copy data */
  switch (entry->type) {
  case JPEG_EXIF_DATATYPE_SBYTE:
  case JPEG_EXIF_DATATYPE_BYTE:
  case JPEG_EXIF_DATATYPE_UNDEFINED:
    /* Unit size is 1-byte */
    memcpy(data->byte_vec, srcptr, size);
    break;

  case JPEG_EXIF_DATATYPE_SSHORT:
  case JPEG_EXIF_DATATYPE_SHORT:
    /* Unit size is 2-byte */
    for (i = 0; i < entry->count; i++) {
      t16 = *(u16*)(srcptr + i * unitsize);
      if (is_be)
        be16_to_cpu(&t16);
      data->short_vec[i] = t16;
    }
    break;

  case JPEG_EXIF_DATATYPE_SLONG:
  case JPEG_EXIF_DATATYPE_LONG:
  case JPEG_EXIF_DATATYPE_FLOAT:
    /* Unit size is 4-byte */
    for (i = 0; i < entry->count; i++) {
      t32 = *(u32*)(srcptr + i * unitsize);
      if (is_be) be32_to_cpu(&t32);
      data->long_vec[i] = t32;
    }
    break;

  case JPEG_EXIF_DATATYPE_DFLOAT:
    /* Unit size is 8-byte */
    for (i = 0; i < entry->count; i++) {
      t64 = *(u64*)(srcptr + i * unitsize);
      if (is_be) be64_to_cpu(&t64);
      *(u64*)(data->ptr + i * unitsize) = t64;
    }
    break;

  case JPEG_EXIF_DATATYPE_SRATIONAL:
  case JPEG_EXIF_DATATYPE_RATIONAL:
    /* Unit size is 4x2=8-byte */
    for (i = 0; i < entry->count; i++) {
      /* First element */
      t32 = *(u32*)(srcptr + i * unitsize);
      if (is_be) be32_to_cpu(&t32);
      data->rational_vec[2*i] = t32;
      /* Second element */
      t32 = *(u32*)(srcptr + i * unitsize + sizeof(u32));
      if (is_be) be32_to_cpu(&t32);
      data->rational_vec[2*i+1] = t32;
    }
    break;

  case JPEG_EXIF_DATATYPE_ASCII:
    /* Copy NULL-terminated string */
    for (i = 0; i < entry->count; i++) {
      data->ascii[i] = *(u8*)(srcptr + i);
      if (data->ascii[i] == '\0') break;
    }
    break;
  }

  return data;
}

/**
 * Show EXIF tags
 */
void jpeg_exif_show_entry (u16 tag, tiff_data_t *data)
{
  int i;

  switch (tag) {
  case JPEG_EXIF_TAGID_IMAGEWIDTH  : printf("Image width\t: "); break;
  case JPEG_EXIF_TAGID_IMAGELENGTH : printf("Image height\t: "); break;
  case JPEG_EXIF_TAGID_IMAGEDESC   : printf("Image description\t: "); break;
  case JPEG_EXIF_TAGID_MAKER       : printf("Maker\t\t\t: "); break;
  case JPEG_EXIF_TAGID_MODEL       : printf("Model\t\t\t: "); break;
  case JPEG_EXIF_TAGID_ORIENTATION : printf("Orientation\t\t: "); break;
  case JPEG_EXIF_TAGID_XRESOLUTION : printf("X Resolution\t\t: "); break;
  case JPEG_EXIF_TAGID_YRESOLUTION : printf("Y Resolution\t\t: "); break;
  case JPEG_EXIF_TAGID_RESUNIT     : printf("Resolution Unit\t\t: "); break;
  case JPEG_EXIF_TAGID_CREATORTOOL : printf("Creator tool\t\t: "); break;
  case JPEG_EXIF_TAGID_MODIFYDATE  : printf("Last modified date\t: "); break;
  case JPEG_EXIF_TAGID_ARTIST      : printf("Artist\t\t\t: "); break;
  case JPEG_EXIF_TAGID_COPYRIGHT   : printf("Copyright\t\t: "); break;
  case JPEG_EXIF_TAGID_EXIF_VERSION: printf("EXIF Version\t\t: "); break;
  default:
    printf("Unknown tag (%d)\t: ", tag);
    break;
  }

  switch (data->type) {
  case JPEG_EXIF_DATATYPE_ASCII:
    printf("%s\n", data->ascii);
    break;

  case JPEG_EXIF_DATATYPE_SBYTE:
  case JPEG_EXIF_DATATYPE_BYTE:
    for (i = 0; i < data->count; i++)
      printf(data->type & 1 ? "%hhu " : "%hhd ", data->byte_vec[i]);
    putchar('\n');
    break;

  case JPEG_EXIF_DATATYPE_SSHORT:
  case JPEG_EXIF_DATATYPE_SHORT:
    for (i = 0; i < data->count; i++)
      printf(data->type & 1 ? "%hu " : "%hd ", data->short_vec[i]);
    putchar('\n');
    break;

  case JPEG_EXIF_DATATYPE_SLONG:
  case JPEG_EXIF_DATATYPE_LONG:
    for (i = 0; i < data->count; i++)
      printf(data->type & 1 ? "%d " : "%u ", data->long_vec[i]);
    putchar('\n');
    break;

  case JPEG_EXIF_DATATYPE_SRATIONAL:
  case JPEG_EXIF_DATATYPE_RATIONAL:
    for (i = 0; i < data->count; i++)
      printf(data->type & 1 ? "%d/%d " : "%u/%u ",
             data->rational_vec[2*i], data->rational_vec[2*i+1]);
    putchar('\n');
    break;

  case JPEG_EXIF_DATATYPE_FLOAT:
    for (i = 0; i < data->count; i++)
      printf("%f ", data->float_vec[i]);
    putchar('\n');
    break;

  case JPEG_EXIF_DATATYPE_DFLOAT:
    for (i = 0; i < data->count; i++)
      printf("%lf ", data->double_vec[i]);
    putchar('\n');
    break;

  case JPEG_EXIF_DATATYPE_UNDEFINED:
    printf("undefined\n");
    break;
  }
}

bool jpeg_exif_read_ifd (tiff_header_t *tiff_header, u32 ifd_offset, u16 len_ifd)
{
  u16 ifd_count, i;
  u32 pos, next_ifd_offset;
  tiff_entry_t *entry_field;
  tiff_data_t *entry_data;

  if (ifd_offset >= len_ifd - 4 ) {
    /* 4 is the minimum ifd length */
    fputs("Invalid IFD offset\n", stderr);
    return false;
  }

  ifd_count = *(u16*)((void*)tiff_header + ifd_offset);
  if (tiff_header->order == JPEG_TIFF_BE)
    be16_to_cpu(&ifd_count);

  for (i = 0; i < ifd_count; i++) {
    /* Read each entry field and convert endianness */
    pos = ifd_offset + sizeof(u16) + i * sizeof(tiff_entry_t);
    if (pos >= len_ifd - sizeof(tiff_entry_t)) {
      /* Out of bound */
      fputs("Invalid IFD count\n", stderr);
      return false;
    }
    entry_field = (tiff_entry_t*)((void*)tiff_header + pos);
    if (tiff_header->order == JPEG_TIFF_BE) {
      be16_to_cpu(&entry_field->tag);
      be16_to_cpu(&entry_field->type);
      be32_to_cpu(&entry_field->count);
      be32_to_cpu(&entry_field->offset);
    }

    /* Read entry data */
    entry_data = jpeg_exif_read_entry(entry_field,
                                      (void*)tiff_header,
                                      tiff_header->order == JPEG_TIFF_BE,
                                      len_ifd);
    if (!entry_data)
      return false;

    if (entry_field->tag == JPEG_EXIF_TAGID_EXIF_IFD ||
        entry_field->tag == JPEG_EXIF_TAGID_GPS_IFD ||
        entry_field->tag == JPEG_EXIF_TAGID_EXIF_IIFD) {
      /* Check IFD / GPS / InteroperabilityIFD pointer type */
      assert (entry_data->type == JPEG_EXIF_DATATYPE_LONG &&
              entry_data->count == 1);

      /* Recursively read child IFD */
      jpeg_exif_read_ifd(tiff_header, entry_data->long_vec[0], len_ifd);
    } else {
      /* Show entry data */
      jpeg_exif_show_entry(entry_field->tag, entry_data);
    }

    /* Free is safe because every union member is a heap pointer */
    free(entry_data->ptr);
    free(entry_data);
  }

  /* Read next IFD */
  pos = ifd_offset + sizeof(u16) + ifd_count * sizeof(tiff_entry_t);
  next_ifd_offset = *(u32*)((void*)tiff_header + pos);
  if (!next_ifd_offset)
    return true; /* Tail of IFD */

  if (tiff_header->order == JPEG_TIFF_BE)
    be32_to_cpu(&next_ifd_offset);
  return jpeg_exif_read_ifd(tiff_header, next_ifd_offset, len_ifd);
}

/**
 * Custom handler for APP1 segment
 * (Suppose this is a function of the external library/plugin
 *  designed in a vulnerable way)
 */
bool jpeg_custom_app1 (jpeg_file_t *jpeg)
{
  u8 *buffer, identifier[6];
  u16 len_field, len_ifd;
  tiff_header_t *tiff_header;

  /* Read the length of this segment */
  if (fread(&len_field, sizeof(len_field), 1, jpeg->file) != 1) {
    fputs("Truncated file\n", stderr);
    return false;
  }
  be16_to_cpu(&len_field);

  /* Allocate buffer for this segment */
  assert (len_field >
          sizeof(len_field) + JPEG_EXIF_IDENTIFIER_LEN + sizeof(tiff_header_t));
  buffer = (u8*)malloc(len_field - sizeof(len_field));
  if (!buffer) {
    perror("Memory error");
    return false;
  }

  /* Read this segment */
  if (fread(buffer, len_field - sizeof(len_field), 1, jpeg->file) != 1) {
    fputs("Truncated file\n", stderr);
    free(buffer);
    return false;
  }

  /* Skip XMP segment (http:) */
  if (memcmp(buffer, JPEG_EXIF_IDENTIFIER, JPEG_EXIF_IDENTIFIER_LEN) != 0) {
    free(buffer);
    return true;
  }

  /* Read TIFF header */
  tiff_header = (tiff_header_t*)&buffer[JPEG_EXIF_IDENTIFIER_LEN];
  len_ifd = len_field - sizeof(len_field) - JPEG_EXIF_IDENTIFIER_LEN;
  if (tiff_header->order == JPEG_TIFF_BE) {
    be16_to_cpu(&tiff_header->type);
    be32_to_cpu(&tiff_header->ifd_offset);
  }

  /* We don't support BIGTIFF */
  if (tiff_header->type != JPEG_TIFF_TYPE_TIFF) {
    fputs("Unsupported TIFF type\n", stderr);
    free(buffer);
    return false;
  }

  /* Read IFD */
  jpeg_exif_read_ifd(tiff_header, tiff_header->ifd_offset, len_ifd);

  free(buffer);
  return true;
}

/**
 * Default handler to skip the segment
 */
bool jpeg_seghandler_default (jpeg_file_t *jpeg)
{
  u16 len_field;

  /* Read the length of this segment */
  if (fread(&len_field, sizeof(len_field), 1, jpeg->file) != 1) {
    fputs("Truncated file\n", stderr);
    return false;
  }
  be16_to_cpu(&len_field);

  /* Skip this segment */
  fseek(jpeg->file, len_field - sizeof(len_field), SEEK_CUR);
  return true;
}

/**
 * Print usage and exit
 */
__attribute__((noreturn))
void show_usage (void)
{
  puts("ExifUtil " VERSION " (" RELEASE_DATE "). Usage:");
  puts("exifutil [-options] jpeg");
  puts("  -f    File to extract EXIF information");

  if (system("/usr/bin/which exiftool > /dev/null") == 0) {
    puts("\n'exiftool' command is also available on your system");
  }
  exit(0);
}

/**
 * Entry point
 */
int main(int argc, char **argv) {
  char opt;
  jpeg_ops_t ops;
  jpeg_file_t *jpeg;
  const char *filepath = NULL;

  /* Parse command line arguments */
  while ((opt = getopt(argc, argv, "f:")) != -1) {
    filepath = NULL;

    switch (opt) {
    case 'f': /* Target file */
      filepath = optarg;
      /* Allocate handlers*/
      ops = jpeg_handlers_new();
      if (!ops)
        continue;
      ops[JPEG_MARKER_APP1] = jpeg_custom_app1;
      break;
    }

    if (filepath) {
      /* Load JPEG file */
      jpeg = jpeg_file_load(filepath, ops);
      if (!jpeg) {
        jpeg_handlers_release(ops);
        continue;
      }

      /* Call handlers */
      printf("File: %s\n", filepath);
      jpeg_walk(jpeg);

      /* Release */
      jpeg_file_release(jpeg);
      jpeg_handlers_release(ops);
    }
  }

  if (filepath == NULL) {
    show_usage();
    return 1;
  }

  return 0;
}
